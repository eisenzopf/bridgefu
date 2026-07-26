//! Shared localhost SIPS/SRTP fixture primitives.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::PathBuf;

use rvoip_sip::{Config as SipConfig, SipTlsMode};

pub fn reserve_udp() -> SocketAddr {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("reserve UDP socket");
    socket.local_addr().expect("reserved UDP address")
}

pub fn reserve_tcp() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve TCP socket");
    listener.local_addr().expect("reserved TCP address")
}

pub struct TestTlsFiles {
    pub directory: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
}

impl TestTlsFiles {
    pub fn create() -> Self {
        let directory =
            std::env::temp_dir().join(format!("bridgefu-sip-tls-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).expect("create TLS fixture directory");
        let cert = directory.join("localhost-cert.pem");
        let key = directory.join("localhost-key.pem");
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("generate localhost certificate");
        std::fs::write(&cert, generated.cert.pem()).expect("write TLS certificate");
        std::fs::write(&key, generated.signing_key.serialize_pem()).expect("write TLS key");
        Self {
            directory,
            cert,
            key,
        }
    }
}

impl Drop for TestTlsFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

pub fn tls_sip_config(
    name: &str,
    udp_address: SocketAddr,
    tls_address: SocketAddr,
    tls: &TestTlsFiles,
    codecs: Vec<u8>,
) -> SipConfig {
    let mut config = SipConfig::local(name, udp_address.port());
    config.sip_tls_mode = SipTlsMode::ClientAndServer;
    config.tls_bind_addr = Some(tls_address);
    config.tls_cert_path = Some(tls.cert.clone());
    config.tls_key_path = Some(tls.key.clone());
    config.tls_extra_ca_path = Some(tls.cert.clone());
    config.contact_uri = Some(format!(
        "sips:{name}@localhost:{};transport=tls",
        tls_address.port()
    ));
    config.offered_codecs = codecs;
    config.offer_srtp = true;
    config.srtp_required = true;
    config
}
