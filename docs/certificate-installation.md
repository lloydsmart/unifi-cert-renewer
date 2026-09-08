# Certificate installation boundary (issue #9)

## Implemented scope

`src/unifi_cert_renewer.py` provides the Python application entrypoint
`run_to_installation()`. It accepts a `UnifiClient`, an `OPNsenseClient`, an
independently configured `CertificatePolicy`, public issuing-CA bytes, and
signing policy. The existing OPNsense client retains its fixed secret-file model
and verified HTTPS policy. The issuing CA is separate from its HTTPS trust store.

The sequence is:

1. Validate signing limits and the configured public issuing CA.
2. Inspect public UniFi metadata and record the complete public certificate chain.
3. Require the configured SPKI baseline; construct and request a CSR in UniFi.
4. Verify CSR proof-of-possession, SPKI, and exact configured subject/DNS/IP SANs.
5. Resolve the OPNsense CA, sign the CSR, and retrieve only the public certificate.
6. Run `validate_issued_certificate()` and construct a canonical public reply.
7. By default, return `state="prepared"` with the request and reviewable plan.
8. With explicit `install=True`, dispatch through the injected import boundary,
   then verify the public keystore result and return
   `state="installed_pending_live_verification"`.

**Preparation is not a dry run:** it creates a signed certificate in OPNsense.
Both result states have `renewal_complete=False`. There is no restart, reload,
live TLS connection, retry loop, threshold check, scheduler, or production CLI.
No production executor is supplied. Tests exercise the complete sequence with
generated in-memory keys/certificates and mocked execution/network seams only.

## Import validation and public reply

`CertificateImportRequest` contains raw public pre-import state, the CSR, the
issued certificate, the configured CA, and the operator's identity policy.
It is not a validation token: `UnifiClient.install_certificate()` always calls
`prepare_certificate_import()` again with the current time before dispatch.
A fabricated dataclass or previously prepared plan cannot skip this path.
There is no application import method accepting an arbitrary PEM reply.

Preparation requires alias `unifi`, entry type `PrivateKeyEntry`, PKCS12/SUN,
matching captured chain length, and matching current/configured/CSR/issued SPKI.
CSR subject and SAN policy are checked before signing, independently of the
identities returned by the CSR generator. Issued-certificate validation includes
the existing exact identity, validity, leaf constraints, and native CA verifier.

This milestone deliberately supports one directly issuing, self-signed CA.
Multiple anchors, intermediate CAs, malformed bundles, invalid CA self-signatures,
and out-of-validity CAs are rejected. The reply is a canonical PEM sequence:
issued leaf first, configured CA second. It contains no unrelated certificates.
Existing leaf/CA input bounds apply; the canonical reply is also bounded.
Only public bytes are passed via standard input; no temporary file is created.

The deterministic import argv uses the observed stdin/chain/`-noprompt` form:

```text
/usr/bin/keytool -importcert -alias unifi
  -keystore /config/data/keystore -storetype PKCS12
  -storepass:env UNIFI_KEYSTORE_PASSWORD
  -keypass:env UNIFI_KEYSTORE_PASSWORD -noprompt
```

This is an argument array, not a shell command. Alias, keystore path, executable,
and password variable name are fixed for the verified deployment baseline.
There is no `-file`, `-trustcacerts`, trusted-alias creation, or key generation.
The password value is never read by this code. The future UniFi-side adapter
must load the existing secret locally into the named child environment variable.
CSR generation uses the existing builder with the same fixed target and explicit
`SHA384withRSA`, consistent with the reported live CSR.

## Documented Java semantics versus live evidence

The [Oracle Java 25 keytool manual][keytool] documents standard-input certificate
replies, X.509 certificate sequences, replacement of a key entry's certificate
chain when the reply key matches, and the private-key password requirement.
For a single leaf, keytool must build a trust chain from available certificates.
A chain reply supplies the CA with the leaf. Our `-noprompt` use relies
on our explicit CA verification; it is not itself a trust check.

[keytool]: https://docs.oracle.com/en/java/javase/25/docs/specs/man/keytool.html

The reported live experiments below confirm the reply form. Neither the manual
nor these experiments establish writer exclusion, atomicity, or crash recovery.

The [issue #9 evidence][issue] supplied on 2026-09-08 records:

* container `unifi-network-application`, LinuxServer image, OpenJDK 25;
* `/usr/bin/keytool`, `/config/data/keystore`, PKCS12/SUN;
* existing `unifi` PrivateKeyEntry, RSA 4096, self-signed certificate;
* a successfully generated CSR for `CN=unifi-mgmt.lloydsmart.com` with
  `DNS:unifi-mgmt.lloydsmart.com` and SHA384withRSA;
* verified proof-of-possession and unchanged SPKI SHA-256
  `95092b344ca9b4e56a34a85088b188be0b3ffe7ff22842afc503c4e25c9d7009`;
* unchanged keystore size/mtime/owner/mode after CSR generation.

[issue]: https://github.com/lloydsmart/unifi-cert-renewer/issues/9

These production identifiers are documentation only, not application defaults
for identity or continuity policy.

### Reported live OpenJDK 25 import experiments

The operator subsequently supplied these results during issue #9 development.
They are operator-reported live evidence, not results of the mocked pytest suite:

1. A bounded PEM reply containing issued leaf followed by CA, supplied on stdin
   to `keytool -importcert -noprompt ...`, succeeds against an existing PKCS12
   PrivateKeyEntry.
2. The alias remains PrivateKeyEntry and the resulting chain length is 2.
3. The installed leaf fingerprint exactly equals the issued leaf fingerprint.
4. SPKI remains unchanged across CSR, issued leaf, and installed leaf.
5. A reply for a different RSA-4096 key is rejected with exit status 1 and the
   diagnostic `Certificate reply does not contain public key for <unifi>`.
6. In that wrong-key experiment, the complete PKCS12 file's SHA-256 was identical
   before and after the failed import. Installed certificate fingerprint and
   SPKI also remained unchanged.

The whole-file comparison is an observation from that particular rejection.
It does not imply that every nonzero exit leaves the file unchanged, or that
interrupted writes are transactional or crash-safe. The renewer neither reads
nor hashes the private keystore; this evidence was collected by the operator
inside the key-owning environment. No raw keystore or private-key fixture is
needed to record it. Tests retain cryptographic pre-import mismatch rejection
and exercise the observed public reply shape; they do not simulate a PKCS12
file and claim to reproduce Java's whole-file behaviour.

## Future executor contract and production gate

`UnifiExecutionBoundary` exposes only public inspection, CSR generation,
certificate-reply import, and an exclusive operation context. It is a trusted
in-process integration seam, not an authorization protocol for remote clients.
A future remote service must not accept arbitrary caller-supplied plans/argv.
Its authorization and validation design requires separate review.

The production executor is intentionally out of scope for this PR. Before adding
one or touching `/config/data/keystore`, establish the remaining deployment
properties. The successful chain reply and unchanged wrong-key rejection above
are established; the following properties must not be inferred from them:

* leaf-only reply fails without an available trusted CA;
* no separate trustedCertEntry is needed and unrelated aliases remain unchanged;
* missing alias and trustedCertEntry are rejected by the guard, because keytool
  may otherwise create or operate on a trusted entry;
* password modifiers, command exit status, and bounded public output capture
  behave as specified under that Java version;
* interrupted import, file replacement, and recovery behaviour are understood;
* LinuxServer startup/UniFi keystore rewrites have been investigated before
  designing a later reload stage.

The adapter must execute direct argv inside the key-owning environment, capture
bounded output with deadlines, discard sensitive diagnostics, and return only
public state/status. Read-only collection of the complete public chain must be
validated against live output; the parser does not bind independently supplied
metadata and DER to a keystore without this trusted collector.

The exclusive context spans fresh inspection, import, and post-import inspection,
including verification of that result. Tests assert that all those calls occur
inside one context and that failures exit without a successful result. This
proves application call ordering; it does not implement a host locking mechanism.
The production executor must guarantee exclusion of every writer throughout
that interval, including other renewer instances, UniFi, and operator tools.
Keytool must not be relied upon for single-writer protection. A shared lock is
adequate only if every possible writer cooperates; otherwise the executor must
quiesce or otherwise exclude non-cooperating writers through a reviewed design.

The application rejects any changed public pre-import state, including a new
certificate on the same key. The adapter receives the fresh expected state and
must protect against replacement between that check and keytool execution.
An advisory Python lock does not stop UniFi or another host process writing the
file. The adapter must also enforce safe path/file identity and an existing
keystore, so an absent/replaced file cannot silently create a new trusted entry.
Do not claim atomicity or deploy until those constraints have a tested design.

## Verification, failures, and recovery

After exit status zero, the application re-inspects public state. It requires
PrivateKeyEntry, unchanged SPKI, the exact issued leaf fingerprint, equal
subject/SAN/issuer/validity metadata, and byte-for-byte equality of the full
leaf-plus-CA DER chain. A human-readable success message is never sufficient.
Any failed check raises an error and yields no successful stage result.

Execution errors contain fixed stage labels and suppress chained diagnostics.
Command output, passwords, API errors, and arbitrary remote text are not logged.
Once import dispatch starts, a timeout, nonzero status, or verification failure
means **the keystore may have changed**. There is no automatic retry or rollback.
The observed wrong-key diagnostic/status is not special-cased as proof that an
arbitrary failed transaction left the keystore unchanged.

A timeout may leave a child process running. Before releasing writer exclusion
or inspecting for recovery, the future executor must establish that the import
process has terminated. It must also define recovery after the renewer itself
dies, including any surviving child; this is not implemented by the Python
context manager. Neither a context exit nor a stale lock proves a write stopped.
Cancellation propagates without returning a stage result. SIGKILL, power loss,
and crash-safe writes have not been tested, and no guarantees are claimed.

Until recovery is proven, production mutation remains unsupported. The intended
failure procedure is to stop the transaction, prevent restart/reload, retain its
public pre-state/issued chain, and let the operator inspect the public state
through the same read-only boundary after excluding writers and establishing
that no import is still running. This must be a fresh inspection, even when an
earlier post-import inspection completed before a context-exit failure. A
previous prepared plan, exit status, or cached inspection cannot establish the
recovered state. If intact, compare against both the old and
issued public chains before deciding what to do. If damaged or changed, escalate
to operator-controlled recovery inside the key-owning environment. Do not
generate a replacement key, delete the alias, or copy the keystore into the
renewer. Any necessary host-owned backup/restore design remains a prerequisite,
not an implemented or proven rollback procedure. There is no persistent recovery
journal or resume command in this milestone. Even an exact issued-chain match on
fresh recovery inspection does not establish a completed renewal.

The next milestone must define a narrow reload mechanism and then open a fresh
verified TLS connection to UniFi. It must enforce configured CA/hostname identity,
validity and constraints, and exact equality to the issued certificate before
reporting renewal success. This mandatory live check is not implemented here.
