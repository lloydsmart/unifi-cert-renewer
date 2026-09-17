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

The supervised renewal path, non-root renewer image, fixed Unix-socket executor,
startup recovery, live TLS finalisation, and signed-tag release pipeline are
implemented. The first complete supervised production renewal succeeded on
2026-09-15. Threshold-based renewal and unattended scheduling are not
implemented, and no release artifact has been published yet.

Security requirements documented here distinguish implemented controls from
requirements for future work. A control is not described as implemented without
corresponding code, tests, or documented production evidence.

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
* copy the keystore containing it into the renewer or outside UniFi appdata;
* mount that keystore into the renewer;
* retrieve the private key through Docker or filesystem access;
* submit private-key material to OPNsense;
* serialize it into logs, exceptions, temporary files, fixtures, or artifacts.

CSR generation must use the existing UniFi private key in place.

Only public CSRs, certificates/chains, and bounded public inspection results may
leave the UniFi key-owning environment.

Issue #12 explicitly permits temporary **whole-keystore staging and rollback
objects inside the protected UniFi appdata/key-owning environment**. They must
never be returned, mounted into the renewer, transmitted, logged, or parsed for
private-key material. They use restrictive ownership and permissions, exist only
for staging/recovery, and must be removed after completed recovery or later
successful live verification. Standalone private-key extraction remains forbidden.
The executor copies whole-keystore data kernel-to-kernel, without reading it into
Python memory. Public inspection uses keytool's certificate-only output.

Direct `keytool -importcert` against the canonical keystore is prohibited:
OpenJDK 25.0.2 destructive write failure was demonstrated in issue #12. A failed
import truncated a disposable PKCS12 after printing a success message. The
executor must mutate an independent stage and validate it before atomic commit.

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

Stage 7 implements this with a fresh socket, a `PROTOCOL_TLS_CLIENT` context,
mandatory `CERT_REQUIRED` and hostname checking, and exact DER equality with the
issued leaf. Connection refusal, reset, and timeout may be retried only within
explicit attempt and deadline bounds. A completed TLS handshake serving a
different valid leaf is an immediate identity failure, including when its SPKI
matches the expected key. Live-verification errors expose fixed diagnostics and
do not include peer data or configured endpoint text.

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

The production identity uses the three-route custom ACL documented in
[`deployment/opnsense/ACL.xml`](deployment/opnsense/ACL.xml). It permits CA
listing, CSR signing, and retrieval of the issued public CRT. It does not permit
certificate deletion, private-key or PKCS#12 export, arbitrary or broader
certificate-store export or management, or generic Trust API access.

## UniFi Access and Orchestration

The Stage-6 application revalidates raw CSR/certificate/CA data and configured
identity policy, compares fresh public pre-state, and verifies the exact public
chain after import. The key-owner-local executor reuses the same validation path
for the stage and committed canonical file. Prepared plans contain public results,
not executable argv or authorization. One directly issuing self-signed CA is
currently supported. Neither preparation nor keystore import completes renewal.

Production mutation has no runtime enable flag or unsafe bypass. The reviewed
fixed Unix-socket protocol is the supported renewer-to-executor cross-boundary
interface. Trusted local root also invokes recovery during startup and can
instantiate the executor within the existing host-root trust model. The server
accepts five semantic operations: public inspection, CSR generation, guarded
installation, recovery, and exact-pending-leaf finalisation. It accepts no
command, executable, argv, alias, service name, pathname, Python function, or
Boolean success assertion. See
[executor and recovery](docs/unifi-executor.md).

The socket directory is a root-owned `0750` bind mount at
`/run/unifi-cert-renewer`; the socket is root-owned, group-owned by that
directory's dedicated deployment group, and mode `0660`. Kernel Unix-socket and
directory permissions authorize only processes in that group. The server and
client both fail closed if owner, group, type, mode, or socket identity is unsafe.
The protocol is local-only, versioned, strictly shaped, length-prefixed and
bounded. One absolute monotonic deadline covers the complete request frame, so
byte trickling cannot retain the single executor indefinitely. A disconnected
client does not cancel an operation that has begun, and response transport
failure is contained to that connection. Failures return one fixed error and
never reflect diagnostics or input. Host root remains the trusted administrator
that assigns the deployment group. A root-created socket interrupted between
bind and final publication is recognized only by its fixed type, mode, owner,
group, link count, device, directory, and listener lock; other entries fail
closed and are not removed.

Writer exclusion covers UniFi through s6 quiescence and actual Java process
inspection, project-controlled renewers through an inherited exclusive lock,
and cooperating automation using the same lock. Host root is a trusted
administrative boundary: the executor cannot prevent a privileged administrator
from bypassing locks, modifying mounts/appdata, or killing the helper. Fresh
file identity and public-state checks detect observable unexpected changes;
they do not claim exclusion of malicious host root. The supplied s6 recovery
oneshot is ordered before LinuxServer's UniFi configuration init. Before strict
recovery, it repairs only the exact root/`abc`-owned executor lock/journal files
that an interrupted LinuxServer recursive ownership pass can leave behind. It
validates fixed names, directory, no-follow opens, type, mode, size, links,
journal structure, reachable phase/flag/artifact combinations, and recorded
transaction inode relationships while holding the pre-existing executor lock.
It never creates a replacement lock beside transaction evidence. Mixed
ownership from an interrupted repair is safe to retry.
The oneshot leaves Java down while deciding and completing startup recovery. A
second fixed oneshot repeats this normalization and recovery inspection after
LinuxServer initialization. The UniFi Java and executor socket longruns depend
on both steps. A corrupt, ambiguous, unsupported, identity-mismatched, symlinked,
or otherwise unsafe state fails closed, so Java cannot race recovery or changed
transaction evidence.

Process inspection requires both the proc executable link and a bounded
NUL-separated command line. For the normal LinuxServer case where root cannot
resolve an `abc` process's executable link, a short-lived child may inspect the
already anchored proc directory only after its ownership and complete status
identity prove the fixed uid/gid `1000:1000`. The child closes unrelated file
descriptors, clears supplementary groups, irreversibly drops all real,
effective, and saved GIDs and UIDs to 1000, and returns only a fixed bounded
classification. `CAP_SYS_PTRACE` is neither required nor granted. Any other
permission failure, identity change, child failure, or same-UID restriction
fails closed; command-line-only matching is never accepted.

A public-only durable journal records service-down intent before stopping UniFi
and blocks another transaction. Explicit recovery obtains exclusion, checks for
surviving keytool processes, quiesces UniFi, and compares fresh public state and
file identities. It may restore the retained old inode atomically, never re-import
or re-sign. Unexpected state requires operator intervention. A surviving or
uninspectable writer retains the helper's lock until operator intervention/helper
exit. Rollback remains after successful commit until Stage 7 verifies live TLS.
The narrow finalisation operation accepts the exact public leaf, requires it to
match the currently pending journal identity, and has no generic success Boolean,
caller-selected transaction, path, command, or executable. It writes
`live_verified` durably before unlinking rollback. Recovery may continue cleanup
only from that state after re-establishing journal-file and directory durability
under the transaction lock. A readable journal replacement is not by itself
proof that its namespace update crossed the directory fsync barrier. Barrier
failure retains rollback. Cleanup also rejects phase-impossible journal fields,
extra keystore hard links, and unexpected stage or temporary-journal artifacts.
A missing rollback under the earlier pending phase is never evidence of
successful verification.

The journal identifies files by runtime device/inode, not a persistent
filesystem identity. A remount or reboot can change a recorded identity and
force operator recovery. This is an intentional conservative limitation, not a
requirement for Btrfs or a reason to ignore a mismatch. Interrupted initial
journal creation or stage ownership setup may also require an operator.
Root-owned artifacts in `abc`-writable appdata rely on excluding all other `abc`
writers during a transaction.

The fixed local protocol is the only supported mechanism for requesting CSR
generation, installation, recovery, and finalisation.

The production renewer container must not receive unrestricted Docker daemon
access.

Do not mount:

```text
/var/run/docker.sock
```

into the renewer.

Access to the Docker socket can normally be converted into host-level control
and would violate the intended privilege boundary.

The production integration uses a permissioned Unix socket and does not require
host orchestration.

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

Container packaging is implemented for a dedicated non-root one-shot renewer and
a narrowly scoped executor overlay in the UniFi image. The renewer runs as
uid/gid `1000:1000`, uses a read-only root filesystem, drops all capabilities,
sets `no-new-privileges`, exposes no inbound listener, and has no restart loop.
It receives only its read-only configuration/secret directory and the shared
runtime directory for the fixed Unix socket, plus membership in the dedicated
socket group. It does not receive UniFi appdata, the UniFi keystore-password
secret, the executor implementation, or the Docker socket.

The worker installs its hash-locked runtime dependencies at build time and
removes pip and the bundled ensurepip installer afterward. Neither setuptools
nor msgpack is a worker runtime dependency; packaging checks reject their
presence along with retained installers. The pinned Bookworm base receives the
exact PCRE2 security update `libpcre2-8-0=10.42-1+deb12u1`. These worker controls
do not change the vendor UniFi application or its executor environment.

The image and Compose example implement these container hardening controls:

* non-root runtime user;
* a read-only root filesystem with a bounded, `noexec`, `nosuid`, and `nodev`
  `/tmp` tmpfs;
* all Linux capabilities dropped;
* `no-new-privileges`;
* no inbound port;
* no Docker socket;
* read-only configuration and secret mounts.

The Compose example attaches the renewer to an operator-controlled external
network so it can reach the stable numeric UniFi live-TLS address. That network
attachment does not itself restrict egress, and neither the image nor the
Compose example implements an egress firewall.

Operators should separately restrict network access, as far as practical, to
the configured OPNsense HTTPS service and the numeric UniFi live-TLS endpoint.
The OPNsense base URL may use a DNS hostname, so deployments using one must also
permit the required DNS resolution through operator-controlled infrastructure.
This egress hardening is a recommendation, not an implemented or
production-proven project control.

The pinned container scanner supports comparison of a derivative image against
the exact reviewed upstream. Derivative-only HIGH or CRITICAL findings are
blockers, including when no fix exists. Inherited HIGH or CRITICAL findings
with an available fix also block unless an exact, explicitly reviewed,
unexpired exception applies. Unfixed inherited findings remain visible for
impact review. Missing or invalid policy inputs fail closed. The
[common image policy](docs/container-image-policy.md) defines exact matching,
review metadata, and the maximum 90-day exception lifetime. The initial
`.security/container-exceptions.json` registry contains no accepted risks.

Supervised pre-release validation may identify local builds by exact image ID.
Once container publishing exists, released production deployment must use the
reviewed registry digest rather than a mutable tag or non-portable local image
ID.

## Release Security

The release workflow preserves a verifiable relationship between:

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

Only a protected `v*` tag push can invoke publication. The workflow requires a
GitHub-verified signed annotated tag that directly targets a commit reachable
from `main`. It builds each image once, validates and scans the exact local image
ID, creates its SBOM from that image, pushes the same image, and verifies the
published digest resolves to the tested Docker config identity. GitHub-native
provenance and SBOM attestations bind the published digest to the workflow.

Release tags matching `v*` are immutable through repository rules. Ordinary
branch pushes, pull requests, and manual workflow runs cannot publish. The
operator procedure and the first-publication GHCR visibility check are in
[`docs/releasing.md`](docs/releasing.md).

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
