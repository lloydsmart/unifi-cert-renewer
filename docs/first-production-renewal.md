# First supervised production renewal

1. Record the current public keystore inspection, leaf fingerprint, chain, and
   SPKI. Confirm the expected SPKI matches configuration. Do not export the
   keystore or private key.
2. Confirm `.cert-renewer-journal`, `.cert-renewer-journal-new`,
   `.cert-renewer-stage`, and `.cert-renewer-rollback` are absent from
   `/config/data`. Preserve the normal protected appdata backup/recovery reference.
3. Restart the derivative UniFi container under supervision. Confirm the recovery
   oneshot reports `no_active_transaction`, the post-init ownership hook succeeds,
   Java becomes ready afterward, and
   `/run/unifi-cert-renewer/executor.sock` is `root:<dedicated-group>` mode `0660`
   beneath a root-owned `0750` directory.
4. From the renewer, perform a public inspection and CSR request first. Then run
   exactly one renewal with installation and the configured live TLS endpoint.
   Do not retry automatically after any failure.
5. Observe the Stage 6 sequence: UniFi stops, the independent stage is imported
   and verified, the rollback/journal become durable, canonical replacement is
   verified, and UniFi resumes.
6. Confirm Stage 7 establishes a fresh CA- and hostname-verified TLS connection,
   matches the exact issued leaf DER, records `live_verified`, and reports
   `renewal_complete` only after final cleanup.
7. Re-inspect the live endpoint and public keystore. Confirm the served leaf,
   chain, and original SPKI, and confirm all four recovery artifacts are absent.

If the executor fails closed, stop. Do not delete/edit transaction files, force
Java up, re-sign, or re-import. Preserve the bounded diagnostic and current file
metadata, keep the appdata backup available, and review the journal/state against
[`unifi-executor.md`](unifi-executor.md) before an explicit recovery decision.
