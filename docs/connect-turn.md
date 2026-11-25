# Use Amazon Connect's TURN relay

Bridgefu 0.9.2 includes merged rvoip 0.5.0 TURN support. The dependency-only
upgrade and TURN implementation have separate commits. The exact TURN dependency revision is in
[`config/rvoip-source.txt`](../config/rvoip-source.txt).

Connect gives each contact a media endpoint and temporary relay credentials.
The current Chime SDK obtains those credentials from `JOIN_ACK`, and marks
`TurnControlUrl` as unused ([credential handling](https://github.com/aws/amazon-chime-sdk-js/blob/main/src/task/JoinAndReceiveIndexTask.ts),
[URL definition](https://github.com/aws/amazon-chime-sdk-js/blob/main/src/meetingsession/MeetingSessionURLs.ts)).
Bridgefu's recommended `auto` mode prefers that same signaling path.
A firewall may block the media endpoint's public address and random UDP port.
Bridgefu can now send that contact's media through Connect's UDP TURN relay
instead. No correlation ID, Lambda context store, or fixed customer field is
required by this networking change.

## Get the release

With the [build prerequisites](../examples/native-sip-webrtc/README.md#start-with-the-local-demo) installed:

```sh
git clone --branch v0.9.2 --depth 1 https://github.com/eisenzopf/bridgefu.git bridgefu-0.9.2
cd bridgefu-0.9.2
cargo build --locked --release
./target/release/bridgefu --version
```

The version must be `bridgefu 0.9.2`. Deploy that binary using your normal
service process, preserving your existing configuration. This source release
does not publish a container image.

## 1. Allow the relay and control traffic

Check [AWS's current network requirements](https://docs.aws.amazon.com/chime-sdk/latest/dg/network-config.html).
AWS currently publishes `99.77.128.0/18` for Chime media, including UDP 3478.
Allow the range and port appropriate to your deployment. Keep DNS, HTTPS/WSS
signaling and AWS API access available, along with the traffic needed by your
SIP provider. The example firewall values are editable; Bridgefu does not
hardcode an AWS destination range.

This implementation supports **TURN over UDP**. It does not provide TURN over
TCP or TLS. A network that permits only TCP 443 still needs a different media
transport implementation.

## 2. Add these settings to your Bridgefu configuration

Merge these keys into the existing sections; retain your region, routes,
credentials and header mappings:

```yaml
aws:
  region: YOUR_AWS_REGION
  turn:
    credential_source: auto
    relay_only: true
    request_timeout_secs: 10

generic_bridge:
  webrtc:
    ice_servers: []
    gather_timeout_secs: 10
    connection_timeout_secs: 30
    turn_attempt_timeout_secs: 2
    turn_send_timeout_secs: 2
    turn_close_timeout_secs: 2
```

`ice_servers: []` disables the default public STUN service. Connect's relay
credentials are still added separately for each contact. `aws.turn.relay_only`
applies to the Connect leg; it does not supply Connect credentials to browser
or other generic WebRTC legs. Leave the generic `ice_transport_policy` at
`all` unless you also configure static TURN for those other legs.

The credential-source choices are:

| Value | What Bridgefu does |
| --- | --- |
| `auto` | Uses usable JOIN_ACK credentials, or fetches them from that contact's `TurnControlUrl`. Recommended. |
| `join_ack` | Uses only the credentials received during Chime signaling. |
| `turn_control_url` | Forces the legacy HTTP credential request. Diagnostic/legacy compatibility option; not recommended for current Connect. |
| `disabled` | Uses only the static ICE servers you configured. |

The legacy URL is not proof that its HTTP operation is available. The live
sandbox rejected the legacy request with HTTP 400 `UnknownOperationException`,
including with the old SDK's version query parameters. Do not force that mode
for this deployment. It fails explicitly instead of silently selecting another
credential source; use `auto` or `join_ack` for the current signaling path.

`relay_only: true` fails the call setup if a UDP relay cannot be allocated; it
does not fall back to a forbidden direct-media destination. The default is
`false` for compatibility with existing configurations. In `auto` mode with
that default, missing TURN credentials may fall back to direct ICE.

You can also set `aws.turn.control_allowed_hosts` to a list of exact HTTPS
control hostnames. An empty list accepts the HTTPS endpoint returned by AWS.
Redirects are disabled. Do not paste temporary TURN usernames or passwords
into your configuration: Bridgefu obtains them for the contact.

For a fixed local firewall port range, additionally set:

```yaml
generic_bridge:
  webrtc:
    udp_port_range:
      bind_ip: 0.0.0.0
      port_start: 42000
      port_end: 42031
```

These ports are examples. Choose your own non-overlapping range and capacity.
Relay-only uses one socket per peer. With policy `all`, TURN may need one
additional socket. The configured range governs both.

## 3. Validate, restart, and make a test call

```sh
bridgefu --config /path/to/bridgefu.yaml validate
```

Restart your Bridgefu service through your usual deployment process. A
successful Connect call records `TURN UDP allocation established` and a
`Connect ICE selected candidate pair` event with `local_candidate_type` equal
to `relay`. These messages contain no relay credentials or media addresses.
Confirm audio in both directions and normal hangup, not just call admission.
Compare each configured Connect attribute against the supplied session, actual
Vapi call ID, and assistant tool arguments. No correlation ID is required for
the SIP-header recipe.

In a disposable QA environment, repeat with Connect TURN disabled and the
same firewall restrictions. Direct media must fail, and the firewall must
record rejected packets. Restore `auto` and `relay_only: true` afterward.
The [automated runbook](../examples/vapi-amazon-connect/tests/TURN.md) performs
these checks and restores its test firewall rules after each case.

If you use the example generator, optional `connect_turn` and `webrtc` objects
in your settings JSON are copied into `aws.turn` and `generic_bridge.webrtc`.
Your chosen SIP headers and contact-attribute mappings stay in `fields`.

## Validation and limits

The separate dependency upgrade passes 790 enabled Rust tests. The TURN library
suite checks relay-only SDP, media in both directions, nominated relay type,
bad credentials, unavailable-server fallback, and allocation removal on close
and drop. The Connect suite checks credential-source selection and configuration
bounds. Local protocol tests do not prove AWS reachability.

The [restricted-egress live runbook](../examples/vapi-amazon-connect/tests/TURN.md)
repeats real Vapi-to-Connect calls with `ice_servers: []`, blocks direct Connect
UDP traffic, and includes a relay-disabled negative control. The November 25
[recorded results](../examples/vapi-amazon-connect/tests/turn-results.json)
qualify the final merged main implementation with `auto`, explicit `join_ack`,
and the required relay-disabled failure. The optional correlation-ID recipe
also passed with `auto`, including missing/expired lookup-token checks.
Positive calls passed two-way audio, exact context mapping, selected-relay,
and cleanup assertions. All disposable test resources were removed and audited.

The exact tested revision still reports version `0.9.1`; the 0.9.2 release
changes version metadata, documentation, and evidence without changing that
production implementation or rvoip pin. The November 24 legacy URL failure
and November 20 unrestricted tests remain separate historical evidence.

Eight unanswered ICE checks followed by a later timeout are consistent with
the current ICE core's retry budget. Candidate checks and the overall failure
deadline are separate. This change supplies a reachable relay candidate; it
does not extend the retry budget or make a blocked destination reachable.

Allocations and permissions are refreshed by the TURN client. Fetching new
Chime credentials during an established contact and replacing TURN servers on
a live peer are not implemented. Create a new peer/contact for new credentials.

## Upstream TURN and ICE regression checks

The pinned rvoip merge includes a [runnable TURN/ICE example](https://github.com/eisenzopf/rvoip/blob/529293064953c94c0b021c43e46d03d878922d0c/docs/TURN_ICE.md).
Its CI gate executes relay-only and direct-ICE calls, verifies exact audio
packets in both directions, and checks local TURN allocation release. Direct
mode uses no ICE servers. A private configuration file supports customer TURN
URLs, credentials, bind settings, and timeouts.

The November 25 live AWS qualification uses the merged rvoip pin above.
The exact Bridgefu revision and binary hash are recorded in `turn-results.json`;
release CI checks are separate from the live AWS run.
