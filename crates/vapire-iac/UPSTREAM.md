# Vapire library snapshot

This directory is a release-build snapshot of
`~/Developer/vapire/crates/vapire-iac` at version `0.1.0`.

The canonical library is developed and tested in Vapire. Bridgefu vendors the
same source temporarily because Vapire does not yet have a repository revision
or published crates.io package that a clean macOS, Windows, or Linux build can
pin. `scripts/check-vapire-iac-snapshot.py` verifies byte parity whenever the
sibling checkout is present. Once `vapire-iac` is published, replace this path
dependency with the exact crates.io version and remove the snapshot.
