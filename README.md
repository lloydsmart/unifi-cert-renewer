# UniFi Certificate Renewer

Provides a supervised renewal path for the HTTPS certificate used by the UniFi
Network Application with an internal OPNsense certificate authority. Automated
threshold monitoring and unattended scheduling are planned but not implemented.

## Status

**The supervised renewal path is implemented and production-proven; unattended
renewal is not implemented.**

The repository currently implements read-only parsing of captured Java
`keytool` metadata, public DER X.509 certificates, and public PEM PKCS#10 CSRs.
CSR inspection cryptographically verifies proof-of-possession and can enforce
public-key continuity using a DER SubjectPublicKeyInfo SHA-256 fingerprint.
The UniFi integration can construct a validated, deterministic
`keytool -certreq` argument vector with explicit DNS/IP SANs and environment
variable password modifiers.

The OPNsense integration implements the narrow Trust API flow needed to resolve
one CA by exact description, submit an already-validated CSR, and retrieve only
the issued public certificate. It requires HTTPS with normal chain and hostname
verification, TLS 1.2 or newer, no redirects, and credentials supplied through
fixed `/run/secrets/opnsense-api-key` and
`/run/secrets/opnsense-api-secret` files. An optional custom TLS CA is identified
by a single filename beneath `/run/secrets`; arbitrary paths are not accepted.
For RSA CSRs it derives OPNsense `key_type` from the CSR and supports 2048,
3072, and 4096-bit keys.
Signing permits SHA-256, SHA-384, or SHA-512 and certificate lifetimes from 1
through 397 days.

Issued-certificate validation now proves exact CSR subject, DNS/IP SAN, and SPKI
continuity; enforces bounded validity and server-leaf constraints; and performs
offline path verification against configured public CA certificate data using
the native `cryptography` X.509 verifier. It accepts exactly these Extended Key
Usage profiles:

* `{serverAuth}`
* `{serverAuth, 1.3.6.1.5.5.8.2.2}`

The second profile is the stock OPNsense `server_cert` result. No other EKU
subset, superset, or additional OID is accepted.

The application entrypoint `run_to_installation()` composes inspection, CSR
generation/validation, OPNsense signing/retrieval, and installation preparation.
Its default signs through OPNsense but stops before UniFi mutation. An explicit
`install=True` exercises the guarded import and post-import checks through an
injected UniFi execution adapter. Supplying an explicit `LiveTLSEndpoint` also
runs Stage 7 and returns `renewal_complete` only after live verification and
executor finalisation. The production adapter uses a fixed Unix-domain socket
to reach a key-owner-local executor inside UniFi. The socket exposes only public
inspection, CSR generation, guarded installation, recovery, and exact-leaf
finalisation. See the [production deployment guide](docs/production-deployment.md).

Stage 6 constructs a validated leaf-plus-CA public reply for the existing
`unifi` PrivateKeyEntry, checks fresh pre-import state, and verifies the exact
public certificate chain after import. The executor imports only into a local
staging keystore, then uses a durable rollback link and atomic replacement.
This first implementation requires one
directly issuing self-signed CA. See
[`docs/certificate-installation.md`](docs/certificate-installation.md) for the
interfaces and live Java findings.

The executor runs exclusively inside the UniFi key-owning environment and uses
s6 stop/start for writer exclusion. Live endpoint verification stays on the
application side; the executor exposes only exact-pending-certificate
finalisation. It does not provide Docker/host orchestration. An s6 recovery
oneshot runs before LinuxServer's UniFi configuration init and is a hard
dependency of the Java longrun. Unsafe or ambiguous recovery state therefore
blocks Java startup. See the [executor and recovery design](docs/unifi-executor.md).
A Stage-6 result is explicitly **not a completed renewal**. The first supervised
production signing, import, live verification, and finalisation completed
successfully on 2026-09-15. Threshold-based renewal and unattended scheduling
remain unimplemented.

The repository includes a dedicated non-root renewer image and a strict production
entrypoint with `inspect`, `csr`, `prepare`, and `install` one-shot modes. It
connects only through `UnifiClient(SocketUnifiExecutionBoundary())`, with the
shared runtime directory and supplemental gid `984`; it receives neither UniFi
appdata, the UniFi keystore-password secret, nor the Docker socket. See the
[production deployment guide](docs/production-deployment.md) and
[first supervised renewal procedure](docs/first-production-renewal.md).

Stage 7 opens a fresh Python TLS connection to an explicit numeric address,
port, and server identity. The numeric address avoids an unbounded DNS lookup
outside the readiness deadline. It uses normal CA-chain and hostname verification,
TLS 1.2 or newer, and exact DER leaf equality with the issued certificate.
PEM or DER issuing-CA input is normalized to canonical PEM and the TLS trust
configuration is constructed before signing or keystore mutation.
Connection startup retries have both deadline and attempt bounds. An
authenticated endpoint serving a different leaf fails immediately. Successful
external verification is recorded as durable `live_verified` journal state
before rollback deletion; interrupted cleanup is repeatable. A failed live
check leaves the Stage-6 rollback and journal intact and does not trigger
signing, import, or automatic rollback.

The implemented supervised path has been validated against a real UniFi
deployment. Threshold policy, unattended scheduling, and release publication
remain future work.

## Intended Renewal Model

UniFi retains ownership of its existing HTTPS private key.

Routine renewal is designed to use that same keypair:

```text
Existing UniFi private key
        |
        | generate CSR in place
        v
Public CSR
        |
        v
UniFi Certificate Renewer
        |
        | OPNsense Trust API
        v
Internal OPNsense CA
        |
        v
Signed public certificate
        |
        v
UniFi Certificate Renewer
        |
        v
Import certificate against existing UniFi keypair
        |
        v
Restart/reload UniFi
        |
        v
Verify live HTTPS certificate
```

The private key must not be exported from UniFi during routine renewal.

## Implementation Stages

1. Read-only inspection of captured UniFi HTTPS certificate and keystore-entry
   data. Parsing and an injected public inspection seam are implemented.
2. CSR command construction using the existing UniFi private key. Argument
   construction, input validation, and key-owner-local execution are implemented.
3. Cryptographic CSR validation. Public PEM parsing, proof-of-possession
   verification, requested SAN/SKI inspection, and SPKI continuity validation
   are implemented.
4. Signing through the OPNsense Trust API. The narrow client and request
   validation are implemented and were exercised in the first production renewal.
5. Validation of the issued certificate. Leaf policy, key continuity, and
   configured-CA path verification are implemented.
6. Installation against the existing UniFi keypair. Validation, public reply
   preparation, staged import, service quiescence, durable recovery journal, and
   exact post-import public-chain verification are implemented. Production
   invocation is restricted by the local socket boundary and was exercised in
   the first supervised production renewal. Disposable Java tests supplement the
   recorded live OpenJDK 25 evidence.
7. Live TLS verification following installation. Fresh verified connection,
   exact issued-leaf equality, durable `live_verified` state, and crash-safe
   finalisation are implemented and production-proven under supervision.
8. Threshold-based one-shot renewal is not implemented.
9. Non-root one-shot container packaging is implemented; external scheduling is
   not yet implemented.

Each state-changing stage will be introduced only after its preceding read-only
and validation stages are testable.

## Production Executor Deployment

Issue #17 supplies a small derivative UniFi image overlay containing the Python
executor and native s6 definitions. The renewer connects to the fixed
`/run/unifi-cert-renewer/executor.sock`; both containers receive only that shared
runtime directory. Its root-owned directory mode (`0750`) and socket mode
(`0660`) authorize the dedicated deployment group. The renewer does not receive
`/config`, the keystore secret, or the Docker socket.

Btrfs is not required. Btrfs, XFS, ZFS, ext4, and other normal local Unraid
filesystems use the same fixed-path, no-follow, file-identity, hard-link,
atomic-replacement, fsync, journal, and fail-closed checks. Btrfs is still
detected so its non-persistent anonymous device-number limitation is explicit.
If a reboot/remount makes a recorded device/inode identity impossible to prove,
startup blocks for operator review instead of weakening identity checks.

Deployment steps and permission checks are in
[`docs/production-deployment.md`](docs/production-deployment.md). The deliberately
supervised first renewal procedure is in
[`docs/first-production-renewal.md`](docs/first-production-renewal.md).

## Verified Deployment Baseline — 2026-09-02

The read-only production observations supplied for issue #2 establish this
LinuxServer UniFi baseline:

* container: `unifi-network-application`
* image: `lscr.io/linuxserver/unifi-network-application:latest`
* Java: OpenJDK 25.0.2
* `keytool`: `/usr/bin/keytool`
* keystore: `/config/data/keystore`
* keystore type and provider: PKCS12 / SUN
* HTTPS alias and entry type: `unifi` / `PrivateKeyEntry`
* certificate chain length: 1
* subject and issuer: `CN=unifi` / `CN=unifi`
* serial number: `808f918252ee91f0`
* validity: 2024-07-23T15:09:36Z through 2034-07-21T15:09:36Z
* certificate SHA-256:
  `3759aa48e57eddf62e30dfc0f94bf01a74ba16fd12dfa7e58115dde73b5544d9`
* public key: RSA 4096
* SAN: `DNS:unifi`
* X.509 SKI (public hex): `efb40cff87c493deeece7ff11e80ee0b2c23da7d`
* DER SubjectPublicKeyInfo SHA-256:
  `95092b344ca9b4e56a34a85088b188be0b3ffe7ff22842afc503c4e25c9d7009`

These observations are historical pre-renewal evidence for the deployment
examined in issue #2. The leaf described above is no longer the current
production leaf. They are not assumptions that every UniFi installation has the
same layout or metadata.

## First Production Renewal — 2026-09-15

The first supervised end-to-end production renewal completed successfully using
source commit `8f8b90e70e0844ae2ff821710a49d07efb7cef59`. It preserved the
historical SPKI SHA-256
`95092b344ca9b4e56a34a85088b188be0b3ffe7ff22842afc503c4e25c9d7009`,
installed issued serial `16`, and independently verified the exact live leaf
SHA-256
`e0272e24b5aba8723ea679f8b45cf5a225bc05daa90ffc3e826de2e600f94346`.
The run returned `renewal_complete=true`, retained keystore ownership and mode,
and removed the transaction artifacts after finalisation. See the
[supervised acceptance procedure and full evidence](docs/first-production-renewal.md).

## Security Principles

The project follows several non-negotiable design rules:

* UniFi owns the HTTPS private key.
* Routine certificate renewal does not rotate that key.
* The renewer must never receive the UniFi private key or keystore. Whole-keystore
  staging/rollback objects are permitted only inside protected UniFi appdata.
* OPNsense owns the CA private key.
* The renewer must never retrieve CA private-key material.
* CSR proof-of-possession and public-key continuity must be verified.
* OPNsense and UniFi TLS connections require normal certificate and hostname
  verification.
* The certificate served after renewal must exactly match the certificate that
  was issued.
* The production renewer container must not receive unrestricted Docker socket
  access.
* Security-scanner exceptions are not enabled by default.

See [`SECURITY.md`](SECURITY.md) for the full security model.

## Development Requirements

The development and dependency-locking baseline targets Python 3.14.
Shared executor code remains syntax-compatible with Python 3.12 because the
current UniFi executor overlay uses its base distribution's Python runtime; CI
therefore tests the shared source on both Python 3.12 and 3.14.

Direct dependencies are declared in:

```text
requirements.in
```

Development, lock-generation, and security-scanning dependencies are declared
separately.

Corresponding `.txt` files are generated, hash-pinned dependency locks.

To regenerate them in a correctly prepared Python 3.14 environment:

```bash
./scripts/compile-requirements.sh
```

Use:

```bash
./scripts/compile-requirements.sh --upgrade
```

only for an intentional dependency refresh.

## Local Checks

Python linting and formatting:

```bash
ruff check .
ruff format --check .
```

Tests:

```bash
pytest
```

Shell syntax:

```bash
for script in scripts/*.sh; do bash -n "$script"; done
bash -n .githooks/pre-commit
```

Dependency scanning uses the pinned security-tool lock.

Secret scanning covers complete reachable Git history.

## Contributing

Development should take place on feature or maintenance branches and be merged
through pull requests.

The `Pull request CI` workflow provides the stable `Required CI gate` check. Once
that workflow exists on the default branch, every pull request receives the gate.
It requires security scanning and the applicable Python tests, dependency-lock
freshness, Ruff lint/format, Markdown lint, Actions lint, and deployment/container
validation. Path-specific work is skipped only after changed-path detection, and
the gate accepts that explicit non-applicable result while failing on failed,
cancelled, or unexpected results. The gate becomes a merge requirement only when
its observed check context is added to the `Protect main` repository ruleset.
Renaming or removing it requires a corresponding ruleset update.

The optional repository commit guard can be enabled with:

```bash
./scripts/setup-git-hooks.sh
```

See [`AGENTS.md`](AGENTS.md) for repository-specific development guidance.

## License

This project is licensed under the GNU General Public License version 3.
See [`LICENSE`](LICENSE).
