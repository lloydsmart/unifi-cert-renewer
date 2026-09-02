# UniFi Certificate Renewer

Automates monitoring and renewal of the HTTPS certificate used by the UniFi
Network Application with an internal OPNsense certificate authority.

## Status

**Initial development.**

The repository currently contains project, dependency, CI, and security
scaffolding. Certificate inspection, CSR generation, signing, installation, and
automated renewal are not yet implemented.

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

1. Read-only inspection of the current UniFi HTTPS certificate and existing
   keystore entry.
2. CSR generation using the existing UniFi private key.
3. Cryptographic CSR validation.
4. Signing through the OPNsense Trust API.
5. Validation of the issued certificate.
6. Installation against the existing UniFi keypair.
7. Live TLS verification following installation.
8. Threshold-based one-shot renewal.
9. Container packaging and external scheduling.

Each state-changing stage will be introduced only after its preceding read-only
and validation stages are testable.

## Security Principles

The project follows several non-negotiable design rules:

* UniFi owns the HTTPS private key.
* Routine certificate renewal does not rotate that key.
* The renewer must never export or copy the UniFi private key or keystore.
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
bash -n scripts/*.sh
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
