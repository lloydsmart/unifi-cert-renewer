# Certificate installation and finalisation boundary (issues #9, #12, and #15)

## Implemented scope

`run_to_installation()` accepts a `UnifiClient`, an `OPNsenseClient`, configured
`CertificatePolicy`, public issuing-CA bytes, and signing policy. It performs:

1. Configuration and issuing-CA validation.
2. Public UniFi inspection and configured SPKI comparison.
3. CSR generation against the existing key and proof-of-possession, subject,
   DNS/IP SAN, and SPKI validation.
4. OPNsense CA resolution, signing, and public certificate retrieval.
5. Issued-leaf validation and canonical leaf-plus-CA reply preparation.
6. By default, return `prepared`; with explicit `install=True`, dispatch the raw
   request to the injected boundary and verify the exact installed public chain.
7. With `install=True`, request the executor's `verify_pending` operation. The
   executor uses protected endpoint/CA policy, makes a fresh authenticated TLS
   connection, compares the served leaf exactly, and finalises the transaction.

**Preparation is not a dry run:** it creates a signed certificate in OPNsense.
`prepared` has `renewal_complete=False`. Only successful executor-owned
Stage 7 verification and cleanup return `renewal_complete=True`.

The production executor exists inside the key-owning boundary. A fixed,
permission-controlled protocol-v2 Unix socket exposes only its five semantic
operations, and the LinuxServer s6 dependency graph runs recovery before UniFi initialization or
Java startup. No Docker interface, generic command transport, or scheduler is
provided. The production entrypoint's read-only threshold decision remains
outside this state-changing orchestration and the executor.

## Validation and interface

`CertificateImportRequest` contains raw public pre-import state, CSR, issued
certificate, configured CA, identity policy, lifetime, exact issued
signature hash/OID, and an internal issuance-freshness reference. It is not an
authorization token. The worker captures its reference after retrieval; the
executor replaces it with its own reference during protocol-v2 preflight. Both
client and executor call `prepare_certificate_import()` with current time for
validity and CA-path checks. Fabricated plans cannot bypass validation. The executor also
checks fresh state before importing and uses `verify_certificate_import()` for
the stage and committed canonical file. The client independently verifies the
post-import public result before leaving its exclusive context.

Preparation requires PKCS12/SUN, alias `unifi`, `PrivateKeyEntry`, matching chain
length, and unchanged current/configured/CSR/issued SPKI. Subject, DNS/IP SANs,
validity, leaf constraints, and the configured CA path are validated. One directly
issuing self-signed CA is currently supported; intermediate chains, multiple
anchors, and invalid CA self-signatures are rejected. At issuance preflight,
`freshness_reference - 5 minutes <= notBefore <= freshness_reference`; a
future-dated leaf is rejected. Later checks reuse that fixed reference while
requiring `notBefore <= current_time < notAfter` and validating the CA path at
current time. `notAfter - notBefore` must equal the requested whole-day lifetime
exactly. Its signature hash and
algorithm OID must equal the protected signing policy. The issuing CA
certificate's own signature digest does not select the leaf signature policy.

Key Usage must be present with only Digital Signature and Key Encipherment set.
Content Commitment, Data Encipherment, Key Agreement, Certificate Sign, and
CRL Sign must all be clear.

Extended Key Usage must be exactly `{serverAuth}` or exactly
`{serverAuth, 1.3.6.1.5.5.8.2.2}`. The latter is the stock OPNsense
`server_cert` profile. A missing EKU, either OID alone without `serverAuth`, any
superset, or any additional OID is rejected. Other non-critical OPNsense
extensions, including Netscape Cert Type, Netscape Comment, SKI, and AKI, are
tolerated when the required policy fields pass.

For automatic `renew`, `renew_before_days` must be less than `lifetime_days`
before inspection. The issued certificate must expire strictly after the
post-retrieval validation time plus `renew_before_days`. Explicit `prepare` and `install` do
not apply this renewal-window check.

`CertificateImportPlan` contains only public reply bytes, exact leaf-first DER
chain, and issued metadata. **It no longer contains argv.** CSR execution accepts
a `CertificatePolicy`; import accepts the raw `CertificateImportRequest`. Neither
method accepts an arbitrary executable, path, alias, command, or password name.

The executor internally constructs fixed keytool arguments. Import targets only
its protected `.cert-renewer-stage` under the open `/config/data` directory,
anchored through `/proc/<helper-pid>/fd/<directory-fd>/`. It supplies `-importcert`,
`-alias unifi`, `-storetype PKCS12`, `-noprompt`, and both password modifiers for
`UNIFI_KEYSTORE_PASSWORD`. Only the validated public reply is supplied on stdin.
The canonical pathname is changed solely by atomic namespace replacement.

## Recorded live evidence

The [issue #9 experiments][issue9] established CSR generation on the existing
RSA-4096 key, valid proof-of-possession, unchanged public key, and unchanged
keystore metadata. OpenJDK 25 accepted a leaf-first, directly issuing CA-second
PEM reply on stdin; the result retained `PrivateKeyEntry`, chain length two,
exact leaf DER, and SPKI. A wrong-key reply was rejected without modifying that
particular disposable file.

The [issue #12 evidence and comments][issue12] established:

* LinuxServer/OpenJDK 25.0.2, `/usr/bin/keytool`, PKCS12/SUN, alias `unifi`.
* Canonical `/config/data/keystore`, mode `0600`, uid/gid `1000:1000` (`abc`).
* An absent alias can silently become `trustedCertEntry`; a pre-existing trusted
  entry rejects the reply. Fresh structural validation is mandatory.
* Leaf-only replies fail without an available trusted CA. Successful replacement
  preserved an unrelated alias in the tested disposable keystore.
* Keytool rewrites PKCS12 in place. A constrained write printed a success message,
  then returned exit 1 and left a truncated unreadable file. **Direct canonical
  keytool mutation is prohibited**, including any assumption that nonzero means
  unchanged.
* The Unraid exclusive appdata share resolves to Btrfs. Disposable tests proved
  independent staging, a rollback hard link, atomic replacement, continued old
  inode visibility through an open FD, and exact original-inode restoration.
* File and directory sync are supported. These experiments did not test actual
  host power loss or storage-controller durability.
* s6 down/up control stopped the actual UniFi Java process and restarted a new
  JVM. Keystore metadata remained unchanged in the observed stop/start cycle.

Production identities and fingerprints are deployment evidence, not defaults
for certificate policy. Current integration tests use generated disposable
PKCS12 files; OpenJDK 25.0.4 was used during issue #12 implementation. Those tests
supplement rather than replace the recorded production 25.0.2 evidence.

[issue9]: https://github.com/lloydsmart/unifi-cert-renewer/issues/9
[issue12]: https://github.com/lloydsmart/unifi-cert-renewer/issues/12

## Transaction and recovery

See [the executor design](unifi-executor.md) for fixed files, process lifecycle,
service exclusion, durable journal transitions, recovery decisions, and deployment
assumptions. Failures never automatically retry import or signing. Successful
filesystem recovery cannot establish successful renewal.

Stage 7 opens a new verified TLS connection, validates the configured CA and
DNS/IP identity through the standard TLS stack, and compares the served leaf
exactly with the issued certificate in DER form. It then calls a narrow executor
operation with that public leaf. The executor requires it to identify the
currently pending issued chain, durably records `live_verified`, and only then
re-establishes the journal-file and directory durability barrier before removing
rollback and journal state with directory synchronization. Journal readability
alone never permits cleanup. The operation
does not accept a generic success assertion or caller-selected transaction,
command, or path. Interrupted cleanup is idempotent; failed TLS verification
leaves recovery material intact.

Production installation is exposed only through the reviewed fixed Unix-socket
boundary and s6 startup recovery integration described in
[the production deployment guide](production-deployment.md). The first supervised
production installation and worker-side live finalisation succeeded on
2026-09-15 under protocol v1; the current executor-owned v2 observation
awaits production acceptance. See the
[recorded execution evidence](first-production-renewal.md#first-production-execution-evidence).
Threshold-based one-shot renewal is implemented in the production entrypoint;
deployment of an unattended external schedule remains future work.
