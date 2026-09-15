# AGENTS.md

## Project Purpose

`unifi-cert-renewer` provides supervised renewal of the HTTPS certificate used
by the UniFi Network Application, using an internal OPNsense certificate
authority. Threshold monitoring and unattended scheduling remain intended
future capabilities.

The project is security-sensitive. Changes can affect certificate trust,
OPNsense CA access, UniFi availability, TLS verification, and management of an
existing private key.

Prefer simple, auditable behaviour over convenience or broad abstraction.

## Current Development State

The supervised end-to-end renewal path is implemented. The first successful
production signing, installation, live TLS verification, and finalisation
completed on 2026-09-15. Read-only inspection, in-place CSR generation and
validation, narrow OPNsense signing, issued-certificate validation, guarded
installation, live verification, the fixed Unix-socket executor boundary, and
non-root one-shot container packaging are represented by code and tests.

Threshold-based renewal, unattended scheduling, CA rollover, and release
publication are not implemented.

Do not assume an interface, container layout, command, file path, keystore
format, or UniFi implementation detail has been validated unless it is
represented by code, tests, or documented live evidence in this repository.

The implementation stages are:

1. Read-only certificate and keystore inspection — implemented and
   production-proven.
2. CSR generation from the existing UniFi keypair — implemented and
   production-proven.
3. CSR validation — implemented and production-proven.
4. OPNsense signing — implemented and production-proven.
5. Signed-certificate validation — implemented and production-proven.
6. Certificate installation against the existing keypair — implemented and
   production-proven under supervision.
7. Live post-install verification — implemented and production-proven under
   supervision.
8. Threshold-based unattended renewal — not implemented.
9. Non-root one-shot container packaging — implemented; unattended scheduling
   and release publication are not implemented.

Destructive or state-changing stages must not be introduced before their
read-only prerequisites are testable.

## Security Invariants

These rules are architectural requirements, not implementation preferences.

### UniFi owns the private key

Routine certificate renewal must use the existing UniFi private key.

The application must not:

* generate a replacement private key during routine renewal;
* export the UniFi private key;
* copy the UniFi keystore into the renewer;
* mount the UniFi keystore into the renewer;
* transmit private-key material to OPNsense;
* write private-key material to logs, terminal output, temporary files, test
  fixtures, or repository files.

CSR generation must occur in the environment that owns the existing UniFi
private key.

Only the resulting public CSR may cross that boundary.

Key rotation is a separate explicit operation and is not part of routine
certificate renewal.

### Key continuity must be proven

A renewal must cryptographically preserve the existing keypair.

Where the implementation has access to the required public information, it
must verify that:

1. the public key represented by the existing UniFi certificate or keystore
   entry is recorded before renewal;
2. the generated CSR contains the expected public key;
3. the CSR proof-of-possession signature is valid;
4. the certificate returned by OPNsense contains the same public key;
5. the installed certificate remains associated with that same keypair.

A certificate whose public key does not match the expected UniFi keypair must
never be installed.

### OPNsense owns the CA private key

The application must never request, retrieve, export, store, or log OPNsense CA
private-key material.

Only the minimum OPNsense Trust API surface required to:

* identify the configured CA;
* submit a CSR for signing; and
* retrieve the resulting public certificate

may be used.

Do not use broader certificate-management APIs merely for convenience.

Any OPNsense endpoint capable of exposing stored private keys must be treated as
out of scope.

### TLS verification is mandatory

OPNsense HTTPS connections and UniFi live-certificate verification must use
normal certificate-chain and hostname verification.

Do not introduce:

* `verify=False`;
* unverified TLS contexts;
* hostname-verification bypasses;
* blanket trust of self-signed certificates;
* silent fallback from verified to unverified connections.

Internal trust must be established explicitly using the configured public CA
certificate.

### Installed-certificate verification is mandatory

Successful certificate import is not sufficient evidence of successful
renewal.

After installation and any required UniFi restart or reload, the application
must establish a new TLS connection and verify the certificate actually served
by UniFi.

The final live certificate must:

* validate to the configured CA;
* match the configured hostname or IP identity;
* satisfy the expected validity and certificate constraints; and
* exactly match the certificate issued during that renewal transaction.

A renewal that cannot prove the live result must report failure.

## Docker and Host Boundaries

Do not grant the production renewer container unrestricted Docker daemon access.

In particular, do not mount:

```text
/var/run/docker.sock
```

into the renewer.

Docker-daemon access is effectively host-level administrative access.

If host-side orchestration is required to execute a narrowly scoped command
inside the UniFi container or restart it, keep that orchestration outside the
renewer or expose only the minimum explicitly designed interface.

Do not solve an integration problem by broadening privileges without first
documenting the trust-boundary change.

## Repository Layout

The current application layout is:

```text
src/
    certificate.py
    csr.py
    production_renewer.py
    unifi_cert_renewer.py
    unifi_client.py
    unifi_executor.py
    unifi_executor_client.py
    unifi_executor_files.py
    unifi_executor_service.py
    unifi_process.py
    unifi_tls.py
    opnsense_client.py
    public_key.py
    secure_file.py
    tls_policy.py

tests/
deployment/
    renewer/
    unifi/
    opnsense/
docs/
```

Keep this list aligned with material integration boundaries. It is not
permission to create unnecessary modules before their responsibilities are
clear.

Keep device-specific operations isolated from orchestration logic.

The main application should express operations such as:

* inspect certificate;
* request CSR;
* validate CSR;
* sign CSR;
* validate certificate;
* install certificate;
* verify live certificate.

Low-level UniFi command syntax should remain inside the UniFi integration
boundary.

## Secrets and Sensitive Files

Do not commit:

* API keys or API secrets;
* passwords;
* private keys;
* Java keystores;
* PKCS#12/PFX files;
* production configuration containing secrets;
* real credential files;
* private CA material.

Secret values should be supplied through dedicated secret files or an
equivalent narrowly scoped deployment mechanism.

Prefer secret-file references over environment variables when practical.

Public certificates, public CA certificates, CSRs, fingerprints, and public
keys are not secret, but still validate them before use.

## Temporary Files

Avoid writing sensitive material to temporary files.

Private-key material must not be written to temporary files at all.

Public CSR and certificate temporary files must:

* use secure creation semantics;
* not follow attacker-controlled symlinks;
* not overwrite unexpected paths;
* be removed when no longer required;
* have bounded size before parsing.

Prefer pipes or standard input/output where doing so produces a simpler and
safer interface.

## Input Validation

Treat configuration, command output, API responses, certificate fields,
filenames, and remote endpoint data as untrusted input.

Validate:

* types;
* lengths;
* expected enumerations;
* certificate encodings;
* UUID/reference formats;
* hostnames and IP addresses;
* filesystem paths;
* CSR and certificate structure.

Do not pass untrusted strings through a shell.

Prefer argument arrays and direct subprocess execution.

## Output and Logging

Never log secrets or private-key material.

Operator-facing text derived from configuration, subprocesses, certificates,
remote APIs, or errors must not permit terminal-control or log-forging
injection.

Errors should disclose enough information to diagnose failures without exposing
credentials or sensitive filesystem contents.

Debug logging does not weaken these rules.

## Dependencies

Python runtime dependencies are declared in `requirements.in`.

Development, lock-generation, and security-scanning dependencies are declared
separately.

All corresponding `.txt` files are generated hashed locks.

Do not edit generated lock files manually.

Regenerate them using:

```bash
./scripts/compile-requirements.sh
```

Use `--upgrade` only for an intentional dependency refresh.

Do not add a dependency when the Python standard library provides a clear,
maintainable, secure implementation.

Dependency additions require justification because this application operates
near certificate authority and management-plane infrastructure.

## Security Scanner Exceptions

The default policy is zero suppressions.

Do not:

* suppress a vulnerability merely to make CI green;
* add blanket scanner exclusions;
* silently ignore secret-scanning findings;
* inherit accepted risks from another project when the affected dependency or
  condition does not apply here.

A future vulnerability exception must be:

* specific;
* documented in `SECURITY.md`;
* justified by actual project requirements;
* linked to tracked remediation work;
* removed when no longer necessary.

## Python Style

Use Python 3.14 for development, dependency locking, scanning, and the renewer
container. Keep shared executor code compatible with Python 3.12 while the
UniFi executor overlay uses that base-distribution runtime.

Use the repository Ruff configuration.

Run:

```bash
ruff check .
ruff format --check .
```

Prefer:

* small functions;
* explicit failure paths;
* type and bounds checking at external boundaries;
* standard-library facilities where suitable;
* deterministic behaviour.

Avoid clever abstractions that obscure security-sensitive state transitions.

## Tests

Tests must not require:

* a real UniFi controller;
* a real OPNsense instance;
* production credentials;
* internet access;
* private keys copied from a live deployment.

Use generated test keys and certificates where cryptographic material is
required.

Important security properties should have explicit tests, especially:

* CSR proof-of-possession;
* public-key continuity;
* SAN validation;
* CA validation;
* certificate/key mismatch rejection;
* malformed API response rejection;
* hostname verification;
* exact live-certificate comparison;
* secret redaction;
* unsafe path handling.

Negative tests are particularly important.

## Git and Pull Requests

Work on a feature or maintenance branch.

Do not commit directly to `main`.

All commits must be cryptographically signed. Unsigned commits must not be
merged.

The repository-provided pre-commit guard may be enabled with:

```bash
./scripts/setup-git-hooks.sh
```

Run before committing:

```bash
git diff --check
```

and the relevant lint, test, lock-freshness, and security checks.

Keep commits focused.

Pull requests should explain:

* what changed;
* why;
* security implications where applicable;
* how the change was tested.

## CI and Releases

GitHub Actions should run with the minimum permissions required by each job.

Pin third-party Actions to immutable commit SHAs.

Dependabot should maintain Python and GitHub Actions dependencies.

The existing Dockerfiles should receive container-specific Dependabot and CI
coverage when that work is introduced. Do not conflate those checks with release
publication.

Release publication should remain separate from ordinary CI.

When container releases are introduced, build, test, scan, and publish the same
source revision, and require digest-pinned released production deployments.

## Documentation Discipline

Do not document planned behaviour as implemented behaviour.

Use explicit language such as:

* planned;
* proposed;
* not yet implemented;
* verified against;
* currently supported.

When live UniFi or OPNsense behaviour is discovered during development, capture
the relevant assumptions in tests or documentation rather than leaving them as
tribal knowledge.

## Scope Discipline

This repository is specifically for UniFi certificate renewal.

Do not prematurely turn it into a generic certificate-management framework.

Common functionality may resemble `aruba-cert-renewer`, but shared abstractions
should only be extracted when multiple real implementations demonstrate a
stable common interface.
