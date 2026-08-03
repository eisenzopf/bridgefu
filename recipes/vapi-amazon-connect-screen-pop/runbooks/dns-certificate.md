# DNS and certificate failure or rotation

## Impact

SIPS connections fail, the stack waits for ACM validation, or certificate age
is below the alarm threshold. Clear SIP is not an acceptable production
workaround.

## Safe checks

1. Confirm the SIP A record resolves to the stack Elastic IP.
2. For a delegated subzone, compare public `NS` answers with the Route 53
   delegation set.
3. Inspect ACM status and every DNS validation CNAME.
4. Through SSM, inspect `bridgefu-cert-refresh.service`, its timer, and
   certificate `notAfter`, SANs, key/certificate match, and file modes.
5. Use `openssl s_client` with SNI against TCP 5061; verify the full chain and
   hostname. Do not print the private key or passphrase.
6. Check `CertificateDaysToExpiry` and active-session metrics.

## Remediation

- Fix delegation/validation records at the authoritative parent and wait for
  public propagation; do not repeatedly replace the ACM resource.
- Restore the runtime role's exact `acm:ExportCertificate` and passphrase-secret
  access if drift removed them.
- Run the refresh unit once. It validates SANs, expiry, and key match before an
  atomic HAProxy reload.
- Bridgefu activates new certificate material only when the active-session sum
  is zero. Drain first; use the documented maintenance window if calls never
  reach zero.
- If issuance cannot complete, roll back the stack update and keep the last
  known-good certificate. Never place a private key in user data or S3.

## Verify

Confirm ACM `ISSUED`, refresh/reload timers active, SNI validation succeeds,
`CertificateDaysToExpiry` is healthy, and a real SIPS/SRTP call passes after
the drain. Retain certificate ARN and timestamps, not certificate key material.
