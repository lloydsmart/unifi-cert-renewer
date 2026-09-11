# UniFi Certificate Renewer

Automates monitoring and renewal of the HTTPS certificate used by the UniFi
Network Application with an internal OPNsense certificate authority.

## Status

**Initial development.**

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
the native `cryptography` X.509 verifier.

The application entrypoint `run_to_installation()` composes inspection, CSR
generation/validation, OPNsense signing/retrieval, and installation preparation.
Its default signs through OPNsense but stops before UniFi mutation. An explicit
`install=True` exercises the guarded import and post-import checks through an
injected UniFi execution adapter. Supplying an explicit `LiveTLSEndpoint` also
runs Stage 7 and returns `renewal_complete` only after live verification and
executor finalisation. A key-owner-local production executor is implemented,
but its mutation, recovery, and finalisation methods are source-gated pending
review. No production CLI or transport is supplied.

Stage 6 constructs a validated leaf-plus-CA public reply for the existing
`unifi` PrivateKeyEntry, checks fresh pre-import state, and verifies the exact
public certificate chain after import. The executor imports only into a local
staging keystore, then uses a durable rollback link and atomic replacement.
This first implementation requires one
directly issuing self-signed CA. See
[`docs/certificate-installation.md`](docs/certificate-installation.md) for the
interfaces, live Java findings, and remaining production-executor requirements.

The executor runs exclusively inside the UniFi key-owning environment and uses
s6 stop/start for writer exclusion. Live endpoint verification stays on the
application side; the executor exposes only exact-pending-certificate
finalisation. It does not provide Docker/host orchestration. See the
[executor and recovery design](docs/unifi-executor.md). A Stage-6 result is
explicitly **not a completed renewal**.
Production signing and import have not been verified by this implementation.
Unattended renewal remains future work.

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

The intended implementation will be developed incrementally and validated
against a real UniFi deployment before unattended renewal is enabled.

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

## Planned Development Stages

1. Read-only inspection of captured UniFi HTTPS certificate and keystore-entry
   data. Parsing and an injected public inspection seam are implemented.
2. CSR command construction using the existing UniFi private key. Argument
   construction, input validation, and key-owner-local execution are implemented.
3. Cryptographic CSR validation. Public PEM parsing, proof-of-possession
   verification, requested SAN/SKI inspection, and SPKI continuity validation
   are implemented.
4. Signing through the OPNsense Trust API. The narrow client and request
   validation are implemented; production signing has not been performed.
5. Validation of the issued certificate. Leaf policy, key continuity, and
   configured-CA path verification are implemented.
6. Installation against the existing UniFi keypair. Validation, public reply
   preparation, staged import, service quiescence, durable recovery journal, and
   exact post-import public-chain verification are implemented. Mutation remains
   disabled pending review. Disposable Java tests supplement the recorded live
   OpenJDK 25 evidence; production deployment is not enabled.
7. Live TLS verification following installation. Fresh verified connection,
   exact issued-leaf equality, durable `live_verified` state, and crash-safe
   finalisation are implemented. Production invocation remains gated.
8. Threshold-based one-shot renewal.
9. Container packaging and external scheduling.

Each state-changing stage will be introduced only after its preceding read-only
and validation stages are testable.

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

These observations describe the deployment examined for the issue; they are
not assumptions that every UniFi installation has the same layout or metadata.

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
* A future renewer container must not receive unrestricted Docker socket access.
* Security-scanner exceptions are not enabled by default.

See [`SECURITY.md`](SECURITY.md) for the full security model.

## Development Requirements

The development and dependency-locking baseline targets Python 3.12.

Direct dependencies are declared in:

```text
requirements.in
```

Development, lock-generation, and security-scanning dependencies are declared
separately.

Corresponding `.txt` files are generated, hash-pinned dependency locks.

To regenerate them in a correctly prepared Python 3.12 environment:

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

The optional repository commit guard can be enabled with:

```bash
./scripts/setup-git-hooks.sh
```

See [`AGENTS.md`](AGENTS.md) for repository-specific development guidance.

## License

This project is licensed under the GNU General Public License version 3.
See [`LICENSE`](LICENSE).
