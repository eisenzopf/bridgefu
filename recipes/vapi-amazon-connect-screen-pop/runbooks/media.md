# SIP/SIPS, audio, and DTMF

## Impact

Vapi transfer is rejected, calls have no or one-way audio, audio quality is
poor, or DTMF does not arrive.

## Safe checks

1. Confirm the requested URI scheme matches the selected posture: `sips:` and
   TLS 5061 for secure production, `sip:` and 5060 only for compatibility.
2. Verify signaling source CIDR, certificate/SNI, one-use token validity, exact
   route, and exactly one valid `X-Correlation-Id`.
3. Inspect call-state and bounded media counters: negotiated codecs, RTP/SRTP
   packet counts, loss, jitter, reorder, duplicate, late drops, transcode
   errors, and cleanup state. Avoid packet payload retention.
4. Confirm the Elastic IP is advertised, UDP 16384-32767 is open, and no NAT or
   proxy rewrites the direct media path.
5. Use synthetic non-silent markers in both directions and RFC 4733 DTMF. A
   signaling-only success is not an audio success.

## Remediation

- Reject malformed, duplicate, expired, or replayed attachments; create a new
  reservation rather than reusing one.
- Restore the approved Vapi signaling CIDRs instead of opening SIP globally.
- Fix SDP/codec mismatch at the endpoint; PCMU and PCMA are the required base
  matrix.
- For one-way audio, correct public address advertisement/security-group return
  path and symmetric RTP learning. Do not relay media through the control API.
- Keep generic outbound WSS DTMF at its published development tier until the
  upstream RFC 4733 defect is fixed and the exact path is requalified.

## Verify

Run PCMU and PCMA calls in both secure and compatibility variants, measure
non-silent audio both ways, DTMF, both hangup directions, zero media queue
drops/transcode errors, and cleanup zero-state. Retain redacted timing/counter
evidence and the exact image/recipe revision.
