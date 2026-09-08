# Security Policy

## Project Security Model

`unifi-cert-renewer` operates between two security-sensitive systems:

* a UniFi Network Application instance that owns the HTTPS private key; and
* an OPNsense certificate authority that owns the CA private key.

The renewer is intentionally designed not to possess either private key.

Its normal certificate-renewal role is to broker public information:

```text
UniFi existing private key
        |
        | signs CSR locally
        v
Public CSR
        |
        v
unifi-cert-renewer
        |
        | HTTPS Trust API
        v
OPNsense internal CA
        |
        | signs CSR
        v
Public certificate
        |
        v
unifi-cert-renewer
        |
        v
UniFi certificate import
```

Preserving that separation is the primary security objective of this project.

## Development Status

The project is currently under initial development and has no stable released
implementation.

Security requirements documented here describe the baseline that future
implementation must satisfy. Documentation must not imply that a control has
already been implemented until corresponding code and tests exist.

## Reporting a Vulnerability

Do not disclose suspected vulnerabilities through a public issue.

Use GitHub's private vulnerability-reporting or security-advisory mechanism for
this repository when available.

If private GitHub reporting is unavailable, contact the maintainer privately
rather than publishing exploit details.

Reports should include enough information to reproduce and assess the problem
without including real production credentials or private keys.

## Private-Key Boundaries

### UniFi private key

The existing UniFi HTTPS private key belongs to the UniFi environment.

Routine renewal must not:

* generate a new private key;
* export the existing private key;
* copy the keystore containing it;
* mount that keystore into the renewer;
* retrieve the private key through Docker or filesystem access;
* submit private-key material to OPNsense;
* serialize it into logs, exceptions, temporary files, fixtures, or artifacts.

CSR generation must use the existing UniFi private key in place.

Only the resulting public CSR may leave the UniFi key-owning environment.

Deliberate key rotation is outside the routine renewal flow and must require a
separate explicit design and operation.

### OPNsense CA private key

The OPNsense CA private key must remain under OPNsense control.

The application must never request or retrieve:

* CA private keys;
* certificate private keys stored by OPNsense;
* PKCS#12 exports containing private material;
* broad certificate-store data that unnecessarily exposes secret material.

The OPNsense integration must use the narrowest API surface that can resolve the
configured CA, sign a CSR, and retrieve the issued public certificate.

## Key-Continuity Requirement

Certificate renewal must not silently become key rotation.

Before installation, the implementation must establish that the public key in
the issued certificate is the same key represented by the UniFi CSR.

Where the UniFi integration permits safe public-key inspection, the renewal
transaction should also establish that the CSR represents the existing UniFi
keypair.

The expected invariant is:

```text
existing UniFi public key
          ==
CSR public key
          ==
issued certificate public key
          ==
post-install UniFi public key
```

A mismatch at any stage is a hard failure.

## CSR Validation

A CSR is public data but must still be considered untrusted input.

Before submitting a CSR to OPNsense, validate at least:

* PEM/DER structure;
* proof-of-possession signature;
* expected public-key algorithm;
* expected key strength;
* expected subject;
* required DNS and IP subject alternative names;
* absence of unexpected identities;
* extension structure and bounds.

Do not allow arbitrary caller-controlled SAN expansion through configuration
without validation.

A malformed or cryptographically invalid CSR must never be sent for signing.

## Issued-Certificate Validation

A certificate returned by OPNsense must be validated before installation.

Validation should include:

* syntactic X.509 validity;
* correspondence with the CSR public key;
* expected subject alternative names;
* expected CA/chain;
* validity interval;
* certificate purpose and relevant key usages;
* signature algorithm policy;
* configured lifetime bounds.

The fact that a response came from the configured OPNsense API is not sufficient
reason to install it.

## Live Post-Installation Verification

A successful import command does not prove that UniFi is serving the expected
certificate.

Following installation and any required reload or restart, establish a fresh TLS
connection to the configured UniFi endpoint.

The live connection must verify:

1. the certificate chain to the configured trusted CA;
2. the configured DNS hostname or IP identity; and
3. exact certificate equality with the certificate issued during the current
   renewal transaction.

The implementation may use bounded retries to accommodate a controlled UniFi
restart, but successful live verification remains mandatory.

If the final certificate cannot be verified, the renewal transaction reports
failure.

## TLS Policy

All HTTPS clients must perform normal certificate validation.

Do not use:

* unverified SSL contexts;
* `verify=False`;
* disabled hostname checks;
* certificate-warning suppression as a substitute for trust configuration;
* silent fallback to plaintext;
* silent fallback to unverified TLS.

Internal CAs must be trusted explicitly through configured public CA material.

Use TLS 1.2 or newer unless future compatibility evidence establishes a stricter
minimum.

## OPNsense API Credentials

OPNsense API credentials are secrets.

Prefer dedicated credential files supplied at runtime.

Do not:

* commit credentials;
* place them in example configuration;
* print them;
* include them in exception messages;
* embed them in URLs;
* copy them into container images.

The OPNsense API identity should have only the privileges required by this
application.

Do not grant broad administrative permissions when a narrower ACL can perform
the required certificate-signing operations.

The final required ACL should be documented and tested against the specific
OPNsense API routes used by the implementation.

## UniFi Access and Orchestration

The stage-6 application currently supplies only an injected execution interface,
tested with mocked adapters. No production host/container executor is provided.
Import always revalidates raw CSR/certificate/CA data and the configured identity
policy, compares fresh public pre-state, and checks the exact public chain after
import. This initial reply format supports one directly issuing self-signed CA.
Preparation performs OPNsense signing but defaults to no UniFi import. Neither a
prepared result nor a verified keystore import is a completed renewal.

See [the installation boundary](docs/certificate-installation.md) for the
recorded live Java findings and the concurrency, safe-path, and recovery requirements that must
be satisfied before implementing production mutation. A command-builder result
or dataclass must not become a remote authorization token.

The future executor must exclude all keystore writers across fresh pre-import
inspection, import, and post-import inspection. Keytool is not assumed to provide
single-writer protection. The observed unchanged PKCS12 hash after wrong-key
rejection does not establish transactional or crash-safe writes. Interrupted or
ambiguous import requires fresh public inspection before recovery decisions and,
in a later milestone, live TLS verification before renewal can be complete.

The mechanism used to request CSR generation, import the certificate, and
restart or reload UniFi must be narrowly scoped.

A future renewer container must not receive unrestricted Docker daemon access.

Do not mount:

```text
/var/run/docker.sock
```

into the renewer.

Access to the Docker socket can normally be converted into host-level control
and would violate the intended privilege boundary.

If host orchestration is required, prefer a small external wrapper or another
explicitly constrained mechanism.

Any design that gives the renewer direct access to the UniFi keystore or Docker
daemon requires a new threat-model review.

## Filesystem and Keystore Safety

Private-key and keystore material must never be committed to this repository.

The `.gitignore` intentionally excludes common private-key and Java/PKCS#12
keystore formats, but ignore rules are only a safety net and not an authorization
mechanism.

Code must not depend on `.gitignore` to protect secrets.

Public CSR and certificate files must still be handled safely:

* use bounded reads;
* reject malformed encodings;
* avoid predictable unsafe temporary files;
* reject unsafe path constructions;
* do not follow unintended symlinks for security-sensitive files;
* use restrictive permissions where files contain credentials.

The renewer should not need direct access to the UniFi keystore during normal
operation.

## Command Execution

Do not construct shell commands containing untrusted values.

Prefer direct subprocess invocation with an argument vector and
`shell=False`.

Treat output from UniFi tooling, Java `keytool`, Docker orchestration, OPNsense,
and configuration as untrusted text.

Validate expected return codes and parse only bounded output.

Do not infer success from human-readable text alone when a stronger
cryptographic verification is available.

## Logging and Terminal Safety

Never emit:

* passwords;
* API keys;
* API secrets;
* authorization headers;
* private keys;
* keystore contents;
* PKCS#12 payloads.

Public certificate metadata, fingerprints, expiry dates, and validated hostnames
may be reported where useful.

Operator-visible text derived from external systems must be escaped or otherwise
handled so control characters cannot inject terminal sequences or forge log
records.

Debug mode must not weaken secret-handling guarantees.

## Configuration Files

Production configuration containing secrets must not be committed.

Example configuration must contain placeholders only.

Configuration should separate:

* non-secret application policy;
* public trust material; and
* secret credentials.

Validate configured hostnames, ports, filesystem paths, renewal thresholds,
certificate lifetimes, SANs, and CA identifiers before performing network or
state-changing operations.

## Dependency Integrity

Direct dependencies are declared in `.in` files.

Resolved dependency trees are committed as hash-pinned `.txt` lock files.

Lock generation uses the pinned tooling defined by this repository.

CI should verify that committed lock files can be regenerated without changes.

Dependency-scanning results apply to runtime, development, tooling, and
security-scanner locks.

## Vulnerability-Scanner Exceptions

The repository starts with **no vulnerability suppressions or accepted CVE
exceptions**.

A scanner finding must not be suppressed merely to obtain a green build.

If an exception becomes genuinely necessary, it must:

1. identify the exact vulnerability;
2. explain why the vulnerable condition is or is not reachable;
3. document compensating controls;
4. identify the dependency or platform constraint preventing immediate
   remediation;
5. link to tracked remediation work;
6. be removed as soon as the constraint disappears.

Broad or permanent suppression patterns are not acceptable.

## Secret Scanning

CI scans complete reachable Git history rather than only the checked-out tree.

A secret removed in a later commit remains compromised if it entered published
Git history.

If a real credential is committed:

1. revoke or rotate it immediately;
2. assess where it was exposed;
3. clean repository history where appropriate;
4. do not treat deletion from the latest revision as remediation.

GitHub native secret scanning and push protection should also be enabled for the
repository where supported.

## Static Analysis

GitHub CodeQL should be enabled from the beginning of application development.

Security-sensitive code paths deserve explicit tests as well as static analysis.

CodeQL does not replace:

* review;
* cryptographic validation;
* dependency scanning;
* secret scanning;
* runtime verification.

## Git Repository Protection

The intended repository baseline is:

* changes to `main` through pull requests;
* force pushes blocked;
* deletion of `main` blocked;
* signed commits required;
* CodeQL enforcement on the protected branch;
* no routine bypass actors;
* release tags matching `v*` protected from update and deletion.

Repository-level rules are part of the security model and should be reviewed
when GitHub settings or release workflows change.

## GitHub Actions

Workflow permissions must follow least privilege.

Third-party Actions must be pinned to immutable commit SHAs rather than mutable
tags.

Pull-request workflows must not expose repository secrets to untrusted code.

Workflows that eventually publish packages or containers should be distinct from
ordinary test workflows and receive only the permissions required for
publication.

## Container Security

Container packaging is not yet implemented.

When added, the intended baseline is:

* non-root runtime user;
* read-only root filesystem where practical;
* dropped Linux capabilities;
* `no-new-privileges`;
* no inbound port unless the design genuinely requires one;
* no Docker socket;
* read-only configuration and secret mounts;
* narrowly restricted network egress;
* image vulnerability scanning;
* reviewed release images rather than automatically tracking mutable tags.

Production deployment should prefer an immutable OCI digest once container
publishing exists.

## Release Security

Release publishing is not yet implemented.

When introduced, release CI should preserve a verifiable relationship between:

```text
GitHub release/tag
        ->
source commit
        ->
tested build
        ->
published artifact
        ->
immutable artifact digest
```

Creating or moving an ordinary branch must not automatically publish a
production release.

Release tags matching `v*` should be immutable through repository rules.

## Tests

Tests must use synthetic credentials and generated cryptographic material.

Do not copy production CSRs, certificates containing sensitive internal
identifiers unnecessarily, credentials, or keystores into test fixtures.

Security properties that require negative tests include:

* invalid CSR signatures;
* unexpected SANs;
* mismatched public keys;
* malformed OPNsense responses;
* invalid certificate chains;
* hostname mismatch;
* expired or not-yet-valid certificates;
* certificate substitution during installation;
* unsafe path inputs;
* control-character injection;
* accidental secret disclosure.

## Current Accepted Risks

There are currently no project-specific accepted vulnerability exceptions.

Future accepted risks must be documented explicitly in this section rather than
hidden in scanner configuration.

## Security Review Triggers

Revisit this threat model before introducing any of the following:

* private-key generation or rotation;
* direct keystore access by the renewer;
* Docker socket access;
* privileged containers;
* SSH access to the Docker host;
* a new OPNsense API endpoint;
* a web service or inbound listener;
* remote management APIs;
* additional certificate authorities;
* support for arbitrary command execution;
* secret storage inside application configuration;
* automatic self-update;
* automatic publication from mutable branches.

A security-sensitive architectural change should be visible in both code review
and documentation.
