#![allow(dead_code)]

//! Hermetic regression for the production StandardCharter handoff contract.
//!
//! This deliberately enters through a real localhost SIP listener. The only
//! fake is the injected Amazon Connect control-plane starter, so the assertion
//! covers Bridgefu config, SIP parsing, tenant routing, custom-header
//! extraction, attribute mapping, and the exact `StartWebRTCContact` request.

#[path = "../src/config.rs"]
mod config;
#[path = "../src/context.rs"]
mod context;
#[path = "../src/imds.rs"]
mod imds;
#[path = "../src/providers.rs"]
mod providers;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use rvoip_amazon_connect::{
    ConnectContactStarter, ConnectError, ConnectScreenPopServer, ConnectionData,
    StartContactRequest,
};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

const GOLDEN_CONFIG: &str = include_str!("fixtures/standardcharter-golden.yaml");
const VAPI_INVITE: &str = include_str!("fixtures/standardcharter-vapi-invite.sip");

struct CapturingStarter {
    captured: Mutex<Option<oneshot::Sender<StartContactRequest>>>,
}

#[async_trait]
impl ConnectContactStarter for CapturingStarter {
    async fn start_webrtc_contact(
        &self,
        request: StartContactRequest,
    ) -> rvoip_amazon_connect::Result<ConnectionData> {
        if let Some(sender) = self.captured.lock().expect("capture lock").take() {
            let _ = sender.send(request);
        }

        // Stop after the control-plane boundary. Chime signaling/media and its
        // teardown behavior are covered in rvoip-amazon-connect's hermetic
        // suite; this test owns Bridgefu's application wiring only.
        Err(ConnectError::Control(
            "golden test stops after StartWebRTCContact capture".into(),
        ))
    }
}

fn available_udp_port() -> u16 {
    std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("reserve UDP port")
        .local_addr()
        .expect("reserved address")
        .port()
}

fn render_invite(server_port: u16, client_port: u16, media_port: u16) -> Vec<u8> {
    let normalized = VAPI_INVITE.replace("\r\n", "\n");
    let (headers, body) = normalized
        .split_once("\n\n")
        .expect("golden INVITE has a header/body separator");
    let body = body
        .trim_end_matches('\n')
        .replace("__MEDIA_PORT__", &media_port.to_string())
        .replace('\n', "\r\n")
        + "\r\n";
    let headers = headers
        .replace("__SERVER_PORT__", &server_port.to_string())
        .replace("__CLIENT_PORT__", &client_port.to_string())
        .replace("__MEDIA_PORT__", &media_port.to_string())
        .replace("__CONTENT_LENGTH__", &body.len().to_string())
        .replace('\n', "\r\n");
    format!("{headers}\r\n\r\n{body}").into_bytes()
}

async fn receive_through_200(client: &UdpSocket) -> Vec<String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut packet = vec![0_u8; 65_535];
    let mut responses = Vec::new();
    loop {
        let (len, _) = tokio::time::timeout_at(deadline, client.recv_from(&mut packet))
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for SIP 200; saw {responses:?}"))
            .expect("receive SIP response");
        let response = String::from_utf8_lossy(&packet[..len]).into_owned();
        let is_200 = response.starts_with("SIP/2.0 200 ");
        responses.push(response);
        if is_200 {
            return responses;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vapi_invite_maps_standardcharter_context_into_start_webrtc_contact() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("rvoip_amazon_connect=debug,rvoip_sip=debug,rvoip_sip_transport=debug,rvoip_sip_dialog=debug")
        .with_test_writer()
        .try_init();
    let sip_port = available_udp_port();
    let yaml = GOLDEN_CONFIG.replace("__SIP_PORT__", &sip_port.to_string());
    let cfg: config::Config = serde_yaml::from_str(&yaml).expect("golden config parses");
    cfg.validate().expect("golden config is valid");

    let (captured_tx, captured_rx) = oneshot::channel();
    let starter = std::sync::Arc::new(CapturingStarter {
        captured: Mutex::new(Some(captured_tx)),
    });
    let server_cfg = cfg
        .into_server_config_with_starter(starter)
        .await
        .expect("Bridgefu builds without AWS or IMDS");
    let server = ConnectScreenPopServer::build(server_cfg)
        .await
        .expect("localhost SIP server builds");
    let serve_task = tokio::spawn(server.clone().serve());
    // `serve` takes its independent event-bus subscription before accepting
    // calls. Yield once so an INVITE cannot race that subscription.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind Vapi test client");
    let client_port = client.local_addr().expect("client address").port();
    let media_port = available_udp_port();
    let invite = render_invite(sip_port, client_port, media_port);
    client
        .send_to(&invite, SocketAddr::from((Ipv4Addr::LOCALHOST, sip_port)))
        .await
        .expect("send golden Vapi INVITE");

    let request = tokio::time::timeout(Duration::from_secs(5), captured_rx)
        .await
        .expect("StartWebRTCContact was invoked before the test deadline")
        .expect("capture sender stayed alive");

    assert_eq!(request.instance_id, "instance-standardcharter-test");
    assert_eq!(request.contact_flow_id, "flow-standardcharter-test");
    assert!(
        request.display_name.to_ascii_lowercase().contains("vapi"),
        "SIP From identity is preserved for the agent display name: {}",
        request.display_name
    );
    assert_eq!(
        request.attributes.get("correlation_id").map(String::as_str),
        Some("+14155550199")
    );
    assert_eq!(
        request
            .attributes
            .get("HostedWidget-customerId")
            .map(String::as_str),
        Some("customer-42")
    );
    assert_eq!(
        request
            .attributes
            .get("HostedWidget-vapiCallId")
            .map(String::as_str),
        Some("vapi-call-77")
    );
    assert_eq!(
        request
            .attributes
            .get("HostedWidget-accountTier")
            .map(String::as_str),
        Some("gold")
    );
    assert_eq!(request.attributes.len(), 4);
    assert!(
        request
            .attributes
            .values()
            .all(|value| value != "must-not-reach-connect"),
        "unallowlisted SIP headers must not cross the Connect boundary"
    );

    let responses = receive_through_200(&client).await;
    assert!(
        responses
            .iter()
            .any(|response| response.starts_with("SIP/2.0 180 Ringing")),
        "the inbound Vapi call rings before acceptance: {responses:?}"
    );
    let accepted = responses.last().expect("response sequence is not empty");
    assert!(accepted.starts_with("SIP/2.0 200 OK"));
    assert!(accepted.contains("Content-Type: application/sdp"));
    let (_, answer_sdp) = accepted
        .split_once("\r\n\r\n")
        .expect("200 response carries an SDP body");
    assert!(answer_sdp.contains("m=audio "));
    assert!(answer_sdp.contains("a=rtpmap:0 PCMU/8000"));
    assert!(answer_sdp.contains("a=rtpmap:101 telephone-event/8000"));

    // Pin the media offer StandardCharter/Vapi currently sends. Full
    // G.711<->Opus frame assertions live with the reusable rvoip bridge.
    let wire_invite = String::from_utf8(invite).expect("fixture is UTF-8");
    assert!(wire_invite.contains("m=audio "));
    assert!(wire_invite.contains("RTP/AVP 0 101"));
    assert!(wire_invite.contains("a=rtpmap:0 PCMU/8000"));
    assert!(wire_invite.contains("a=rtpmap:101 telephone-event/8000"));

    serve_task.abort();
    let _ = serve_task.await;
}
