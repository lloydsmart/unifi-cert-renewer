# Supervised production acceptance renewal

This is the acceptance procedure for the first production deployment and for a
materially changed build or deployment whose renewal path must be requalified.
It can be repeated when qualifying such changes. A routine supervised renewal
does not necessarily repeat the build, scan, derivative deployment, restart, or
deliberately unused `prepare` certificate steps below. Threshold decisions,
scheduling, and automatic retries are not part of this procedure.

1. Record the current public keystore inspection, leaf fingerprint, chain, and
   SPKI. Confirm the expected SPKI matches configuration. Do not export the
   keystore or private key.
2. Confirm `.cert-renewer-journal`, `.cert-renewer-journal-new`,
   `.cert-renewer-stage`, and `.cert-renewer-rollback` are absent from
   `/config/data`. Preserve the normal protected appdata backup/recovery reference.
3. For a released deployment, record the tested derivative image's registry
   digest and confirm the UniFi deployment references that exact digest, not a
   mutable tag. During explicitly supervised pre-release validation, record and
   verify the exact local image ID instead; do not present it as a portable
   registry reference. Restart the derivative UniFi container under supervision.
   Confirm the recovery
   oneshot reports `no_active_transaction`, the post-init ownership hook succeeds,
   Java becomes ready afterward, and
   `/run/unifi-cert-renewer/executor.sock` is `root:<dedicated-group>` mode `0660`
   beneath a root-owned `0750` directory.
4. Build and scan the dedicated renewer image as described in
   [`production-deployment.md`](production-deployment.md). Record its registry
   digest for a released deployment or its exact local image ID for supervised
   pre-release validation. Inspect the resolved Compose definition. Confirm
   uid/gid `1000:1000`, supplemental gid
   `984`, and only the shared runtime and renewer-secrets mounts. Confirm it has
   no `/config`, UniFi keystore-password secret, Docker socket, capabilities, or
   restart loop.
5. Populate the fixed `renewer-config.json`, API credential files, public
   issuing CA, and optional OPNsense HTTPS CA. Validate their owner/mode policy.
   Do not place the UniFi keystore password in this directory.
6. Run the public gates first:

   ```bash
   docker compose -f deployment/renewer/compose.example.yaml run --rm renewer inspect
   docker compose -f deployment/renewer/compose.example.yaml run --rm renewer csr
   ```

   Record the public certificate and CSR metadata. Confirm subject, SANs, and
   SPKI are exactly expected and the CSR signature is valid. Neither command
   signs or mutates UniFi.
7. Run one preparation pass under supervision:

   ```bash
   docker compose -f deployment/renewer/compose.example.yaml run --rm renewer prepare
   ```

   This creates and validates a certificate in OPNsense but does not install it.
   The renewer does not persist this candidate. Review the resulting public
   metadata; the later install mode deliberately starts a fresh transaction and
   signs a new certificate.
8. Request exactly one complete installation with the configured live TLS
   endpoint:

   ```bash
   docker compose -f deployment/renewer/compose.example.yaml run --rm renewer install
   ```

   Do not retry automatically after any failure.
9. Observe the Stage 6 sequence: UniFi stops, the independent stage is imported
   and verified, the rollback/journal become durable, canonical replacement is
   verified, and UniFi resumes.
10. Confirm Stage 7 establishes a fresh CA- and hostname-verified TLS connection,
   matches the exact issued leaf DER, records `live_verified`, and reports
   `renewal_complete` only after final cleanup.
11. Re-inspect the live endpoint and public keystore. Confirm the served leaf,
   chain, and original SPKI, and confirm all four recovery artifacts are absent.
12. Remove unused OPNsense certificate records created by supervised `prepare`
    passes or failed attempts. Perform this as a separate operator cleanup using
    an appropriately authorized administrative path; the renewer's narrow ACL
    deliberately has no delete privilege. Confirm the successfully installed
    certificate record is retained.

If the executor fails closed, stop. Do not delete/edit transaction files, force
Java up, re-sign, or re-import. Preserve the bounded diagnostic and current file
metadata, keep the appdata backup available, and review the journal/state against
[`unifi-executor.md`](unifi-executor.md) before an explicit recovery decision.

Unattended scheduling, threshold checks, automatic retries, and general
daemonisation remain out of scope. Each command above is a separate manual
one-shot invocation.

## First production execution evidence

The procedure completed successfully on 2026-09-15 using merged source commit
`8f8b90e70e0844ae2ff821710a49d07efb7cef59`. The supervised pre-release
deployment recorded exact local image IDs, not registry digests:

* renewer:
  `sha256:98fb1e1f222e19ac37148ebb17fc861f025830fa8dc6344c37be4ca0f2c9678c`
* UniFi derivative:
  `sha256:a7e8d8805f637b77dcd983e8f103208b5e5b80f5acecf2e6d8b1ef6bed32649c`

The run returned `renewal_complete=true` for issued leaf serial `16`. The issued,
installed, and independently observed live leaf shared SHA-256
`e0272e24b5aba8723ea679f8b45cf5a225bc05daa90ffc3e826de2e600f94346`.
The SPKI SHA-256 remained
`95092b344ca9b4e56a34a85088b188be0b3ffe7ff22842afc503c4e25c9d7009`.
Independent CA- and hostname-verified live TLS inspection connected to the then
observed `172.26.0.3:8443`, authenticated `unifi-mgmt.lloydsmart.com`, and
matched the installed leaf exactly. That observed address is execution evidence,
not a safe configuration default; future runs require an operator-controlled
stable numeric address. After finalisation, the keystore remained mode `0600`
and ownership `1000:1000`, and `.cert-renewer-journal`,
`.cert-renewer-journal-new`, `.cert-renewer-stage`, and
`.cert-renewer-rollback` were absent.

Post-run cleanup of unused OPNsense certificate records from supervised
preparation and failed attempts must use a separate administrative path; the
renewal ACL must not be broadened for cleanup.
