# SIP application to interactive WebRTC

`sip-webrtc-bridge@1` accepts a one-use SIP attachment and originates one
fixed interactive WebRTC WSS destination. It is the starting recipe for SIP
applications that must interoperate with a browser-shaped or CCaaS WebRTC
interface while keeping the outbound target and credentials server-owned.

**Support tier: `preview`.** The data-only package and runtime projection are
implemented. Promotion requires retained SIP/RTP, SIPS/SRTP, WSS, ICE/TURN,
codec, DTMF, DataChannel, hangup, adverse-network, load, and soak evidence for
the exact release.

SIPS/SRTP is the default. The clear SIP/RTP posture is explicit and should be
limited to a private or provider network. The WSS bearer token is optional and
must be a late-bound secret reference. It is never part of the target URI,
recipe fingerprint, output, or logs.

The application backend creates the call through the authenticated Bridgefu
API and hands the SIP application a short-lived attachment URI. The inbound
signaling network is additionally constrained to the configured CIDRs. Opus,
PCMU, and PCMA are the declared interoperability set.
