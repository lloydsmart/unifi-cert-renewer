# Contributing to UniFi Certificate Renewer

Contributions are welcome. This project changes certificate trust and access to
UniFi and OPNsense, so keep changes small and reviewable.

## Ways to contribute

* Report bugs with a reproducible, redacted example.
* Propose security-safe features that fit the UniFi renewal scope.
* Improve documentation and operational guidance.
* Add tests, especially for failure paths and security properties.
* Submit implementation fixes.

Report suspected vulnerabilities through [SECURITY.md](SECURITY.md). Do not
file exploit details in public issues.

## Before opening a change

1. Branch from `main`.
2. Read [AGENTS.md](AGENTS.md).
3. Read [SECURITY.md](SECURITY.md) before a security-sensitive change.
4. Keep the change focused on one problem.
5. Use generated test material. Never use real credentials, private keys,
   keystores, or production secrets in code, tests, logs, or PR attachments.
6. Preserve certificate verification, TLS verification, and private-key
   boundaries even when a shortcut would simplify the implementation.

## Development setup

Python 3.14 is the primary development and renewer runtime version. Shared
executor code remains compatible with Python 3.12. Use a local Python 3.14
environment when available; CI covers both versions. A local 3.14 installation
is not required merely to propose a documentation or narrowly scoped change.

Create a virtual environment and install the committed hash-pinned locks:

```bash
python3.14 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements.txt
python -m pip install --require-hashes -r requirements-dev.txt
```

Do not choose dependency versions independently or edit generated lock files
by hand. When changing dependencies, regenerate locks with
`./scripts/compile-requirements.sh` in a prepared Python 3.14 environment.

## Required checks

Run the checks relevant to your change before opening a PR:

```bash
ruff check .
ruff format --check .
pytest
git diff --check
```

CI tests Python 3.12 and 3.14, checks dependency lock freshness, scans pinned
dependencies, and scans complete reachable Git history for secrets. The
repository scripts `./scripts/scan-dependencies.sh` and
`./scripts/scan-secrets.sh` provide the corresponding local checks when their
Python 3.14 or Docker prerequisites are available. Run Markdown lint with
`markdownlint-cli2 '**/*.md'` for documentation changes. Run the relevant
deployment and container checks for changes to images, Compose definitions,
the executor, or release packaging; see the scripts and CI workflows for
their required image inputs.

## Security-sensitive changes

UniFi retains its HTTPS private key; OPNsense retains the CA private key.
Preserve exact public-key continuity from the existing UniFi keypair through
the CSR, issued certificate, and installed certificate. Never bypass TLS
chain or hostname verification. State-changing operations need testable
read-only prerequisites. Do not broaden Docker, host, or OPNsense privileges
to make an integration change easier. Vulnerability exceptions must be exact,
reviewed, temporary, documented, and linked to tracked remediation.

[AGENTS.md](AGENTS.md) and [SECURITY.md](SECURITY.md) contain the authoritative
requirements and threat model.

## Pull requests

Target `main` and keep the PR focused. Explain what changed, why it changed,
any security or trust-boundary implications, and which checks you ran. Include
production or live evidence only when you actually performed that verification.
All commits must be cryptographically signed. Never attach generated credentials,
private keys, keystores, or production secrets.

## Licensing

Contributions are made under this repository's GPL-3.0 license. See
[LICENSE](LICENSE).
