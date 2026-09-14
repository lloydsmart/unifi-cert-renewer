# First supervised production renewal

1. Record the current public keystore inspection, leaf fingerprint, chain, and
   SPKI. Confirm the expected SPKI matches configuration. Do not export the
   keystore or private key.
2. Confirm `.cert-renewer-journal`, `.cert-renewer-journal-new`,
   `.cert-renewer-stage`, and `.cert-renewer-rollback` are absent from
   `/config/data`. Preserve the normal protected appdata backup/recovery reference.
3. Record the tested derivative image's registry digest and confirm the UniFi
   deployment references that exact digest, not a mutable tag. Restart the
   derivative UniFi container under supervision. Confirm the recovery
   oneshot reports `no_active_transaction`, the post-init ownership hook succeeds,
   Java becomes ready afterward, and
   `/run/unifi-cert-renewer/executor.sock` is `root:<dedicated-group>` mode `0660`
   beneath a root-owned `0750` directory.
4. Build, scan, push, and record the dedicated renewer image digest as described
   in [`production-deployment.md`](production-deployment.md). Inspect the
   resolved Compose definition. Confirm uid/gid `1000:1000`, supplemental gid
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

If the executor fails closed, stop. Do not delete/edit transaction files, force
Java up, re-sign, or re-import. Preserve the bounded diagnostic and current file
metadata, keep the appdata backup available, and review the journal/state against
[`unifi-executor.md`](unifi-executor.md) before an explicit recovery decision.

Unattended scheduling, threshold checks, automatic retries, and general
daemonisation remain out of scope. Each command above is a separate manual
one-shot invocation.
