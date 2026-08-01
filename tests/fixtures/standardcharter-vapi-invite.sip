INVITE sip:banking@127.0.0.1:__SERVER_PORT__ SIP/2.0
Via: SIP/2.0/UDP 127.0.0.1:__CLIENT_PORT__;branch=z9hG4bK-standardcharter-golden;rport
Max-Forwards: 70
From: "Vapi caller" <sip:vapi@127.0.0.1:__CLIENT_PORT__>;tag=vapi-golden
To: <sip:banking@127.0.0.1:__SERVER_PORT__>
Call-ID: standardcharter-golden@127.0.0.1
CSeq: 1 INVITE
Contact: <sip:vapi@127.0.0.1:__CLIENT_PORT__>
x-correlation-id: +14155550199
X-Vapi-Customer-Id: customer-42
X-Vapi-Call-Id: vapi-call-77
X-Account-Tier: gold
X-Not-Allowlisted: must-not-reach-connect
Content-Type: application/sdp
Content-Length: __CONTENT_LENGTH__

v=0
o=vapi 1 1 IN IP4 127.0.0.1
s=standardcharter-golden
c=IN IP4 127.0.0.1
t=0 0
m=audio __MEDIA_PORT__ RTP/AVP 0 101
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
