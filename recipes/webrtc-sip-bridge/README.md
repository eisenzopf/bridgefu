# Browser WebRTC to SIP contact center

`webrtc-sip-bridge@1` accepts a short-lived, one-use WebRTC attachment and
originates one fixed SIP destination. It is the starting recipe for a website
voice experience that transfers to a SIP contact center without letting the
browser choose a carrier, URI, proxy, or credential.

**Support tier: `preview`.** The data-only package and runtime projection are
implemented. Promotion requires retained browser, ICE/TURN, WSS, codec, DTMF,
Digest, SIPS/SRTP, clear compatibility, hangup, adverse-network, load, and soak
evidence for the exact release.

SIPS/SRTP is the default. Set `sip_security: sip_rtp` only for a restricted
compatibility network, and make the target/from/proxy URIs use `sip:`. Digest
authentication is optional; when used, supply the username and password
reference together. The password value is resolved only at the outbound SIP
operation boundary and is excluded from recipe fingerprints and diagnostics.

The application backend—not browser JavaScript—uses the authenticated
Bridgefu API to create the call and gives the browser its one-use WebRTC
attachment. The destination remains server-owned. Opus, PCMU, and PCMA are the
declared interoperability set; negotiated media remains full duplex.
