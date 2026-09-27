# Protected policy and executor-owned live verification (protocol v2)

This describes the current source implementation. It has local test coverage but
has **not** yet been accepted against a production UniFi deployment. The
2026-09-15 production evidence describes the earlier protocol v1 images.

## Trust boundary

The ordinary renewer worker orchestrates inspection, OPNsense signing and
installation. It can read public policy, CA and leaf data, and can invoke every
operation on its Unix socket. It cannot choose the certificate-use policy or
attest completion. The root executor in the UniFi container independently loads
a host/operator-controlled public policy from
`/run/unifi-cert-renewer-policy/policy.json` before publishing its socket. It
keeps the parsed object for its process lifetime.

The **same exact host policy directory** must be mounted read-only into both
containers at `/run/unifi-cert-renewer-policy`. The renewer Compose example
already includes this mount. Add the following bind to the existing UniFi
service, alongside its separate socket and keystore-password mounts:

```yaml
- type: bind
  source: ${RENEWAL_POLICY_DIRECTORY:?set RENEWAL_POLICY_DIRECTORY}
  target: /run/unifi-cert-renewer-policy
  read_only: true
```

Use a root-owned `0755` directory and a root-owned regular `0644`
`policy.json` so the non-root worker can read this public artefact. Neither may
be group/other writable. The executor rejects symlinks, oversized
files, unsafe owners/modes and malformed policy. Worker readability is expected.
Do not mount worker credentials or the UniFi password with this public policy.
The worker's own `/run/secrets/renewer-config.json` contains only its stale-SPKI
assertion, OPNsense connection details, certificate description and renewal
threshold. The OPNsense API credentials remain in worker-only secret files.

Start from [the policy example](../deployment/renewer/policy.example.json), replace
the placeholder with **one exact public PEM issuing CA certificate** encoded as
a JSON string (newlines escaped), and set the reviewed identity and endpoint.
The example is deliberately invalid until its CA is replaced. The policy binds:

- schema version 2; subject and complete DNS/IP SANs;
- the exact directly issuing self-signed CA certificate and its worker-facing
  OPNsense description;
- lifetime in days, issued-leaf signing digest and exact RSA signature OID;
- fixed CSR signature policy `SHA384withRSA`;
- numeric TLS connection address, port, separate DNS/IP TLS identity and bounded
  readiness settings (overall timeout at most 120 seconds).

The executor derives the current SPKI from its own public keystore inspection.
The worker's SPKI value is only a stale-state assertion. It is not a persistent
authorisation field in the protected policy.

The policy identifier is SHA-256 of the **exact file bytes**. It detects drift;
it is public and grants no access. The executor compares the worker's assertion
on CSR and install requests with its own startup-loaded digest. Every new
transaction journal records that digest. Change the file only by replacing the
host-controlled artefact and restarting the executor; there is no hot reload.

## Protocol and completion

Protocol v2 has five fixed operations: `inspect`, `generate_csr`, `install`,
`recover` and `verify_pending`. CSR generation accepts the policy digest and
expected SPKI assertion, then uses executor-owned identity fields. Installation
accepts the digest plus public before-state, CSR and issued certificate. The
executor reconstructs the import request using its own subject/SAN, CA and
lifetime policy and checks the fixed CSR and issued-leaf signature policies.
Mismatch or unknown fields fail before the journal or UniFi service changes.
Protocol v1 mutation and `finalize` requests are rejected.

`verify_pending` accepts no arguments. Under the transaction lock, the executor
requires a policy-matching pending journal, validates committed and rollback
state, derives the expected leaf from the local canonical keystore and checks its
journal identity. It then makes a fresh TLS connection using only its protected
numeric address, port, TLS identity and CA. Normal chain and hostname/IP
verification and exact leaf-DER equality must succeed. The executor rechecks
local state before durably writing `live_verified`, then retains the existing
fsync and cleanup order. The worker can request the operation but cannot supply
leaf evidence, a success assertion, endpoint settings or a token.

A TLS failure or crash before the trusted `live_verified` transition leaves the
journal and rollback. Existing recovery completes cleanup after a durable
trusted transition; it does not infer success from a missing rollback in a
pending state. A policy digest mismatch fails closed. No automatic new signing,
destructive rollback or policy reinterpretation is performed.

## Quiescent upgrade and rollover

**Require no active `.cert-renewer-journal` before enabling protocol v2.**
Version 1 `live_verified` records could have been made with worker-supplied
public leaf data and cannot be trusted as v2 evidence. Version 2 rejects
old-format journals rather than automatically migrating or cleaning them. If
one exists, stop the upgrade and follow supervised recovery with the old
deployment or an explicitly reviewed operator procedure. Do not delete or edit
journal/rollback files to force progress.

For a policy change or CA rollover, finish every pending transaction under its
recorded policy first. Then atomically replace the protected host artefact while
the executor is stopped, restart the executor and worker deployment with the
same file, and inspect their resolved mounts and policy digests. A pending
journal under a different digest blocks verification and recovery. Do not
reinterpret it under a new CA.

The worker and UniFi images must be upgraded together: both speak protocol v2.
An old/new mismatch fails before mutation. The protected policy directory is a
new mount in both; keep the existing socket directory, worker-only OPNsense
secrets and UniFi-only keystore password separate.

## Deployment acceptance still required

Before authorising production use, establish from **inside the UniFi executor
container** that the configured numeric address and port are reachable and
represent the TLS service operators intend to attest. Confirm the configured
TLS identity and CA authenticate that endpoint. The historical worker-side
observation does not prove this network view. If TLS terminates elsewhere and
the executor observes a different endpoint, revisit the architecture rather
than treating that observation as completion evidence.
