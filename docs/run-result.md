# Structured run result (schema version 1)

`--output json` selects one schema-v1 JSON object and one trailing newline on
stdout for each normally handled application invocation. The default remains
the compact legacy JSON on success, bounded stderr on failure, and legacy JSON
for a busy application lock. CLI parse errors retain exit 2 and the fixed usage
line without a result document. Abrupt process death can also prevent output.

## Fields and closed values

Each top-level result has exactly `schema_version` (integer `1`), `product`
(`unifi`), `operation`, `attempt_id` (UUIDv4), `started_at`, `finished_at` (UTC
RFC3339 at second precision), `outcome`, `stage`, `manual_recovery_required`,
`reason_code`, `message`, and `results`. The attempt ID is created after valid
CLI parsing and before the lifecycle lock, configuration, or network work. It
is unrelated to the executor transaction ID. There is one result object with
`target: "unifi"` per invocation; the target never reveals a deployment identity.

Each target result has exactly `target`, `outcome`, `stage`, `renewal_due`
(boolean or null), `change`, `manual_recovery_required`, `reason_code` (or null),
`message`, `certificate` (or null), and `milestones`. Validated public
certificate metadata contains only `fingerprint_sha256` (lowercase DER SHA-256)
and `expiry_date` (`YYYY-MM-DD`). Messages are fixed project text.

The operation vocabulary is `inspect`, `renew_due`, `renew_now`, `generate_csr`,
`retrieve_csr`, `sign_csr`, and `install`. UniFi emits only:

| UniFi mode | Schema operation |
| --- | --- |
| `inspect` | `inspect` |
| `csr` | `generate_csr` |
| `prepare` | `sign_csr` |
| `install` | `install` |
| `renew` | `renew_due` |

Outcomes are `success_changed`, `success_no_change`, `success_prepared`,
`attention_due`, `failure_pre_attempt`, `failure_partial`, and
`failure_ambiguous`. Stages are `startup`, `configuration`, `lock`, `inspection`,
`decision`, `preflight`, `csr_generation`, `csr_retrieval`, `signing`,
`issued_validation`, `installation`, `activation`, `live_verification`,
`finalization`, and `completed`. Reasons are `config_invalid`, `lock_busy`,
`lock_failed`, `pending_state`, `inspection_failed`, `csr_failed`,
`signing_failed`, `validation_failed`, `installation_failed`,
`verification_failed`, `recovery_required`, and `unexpected_failure`.
`change` is `none`, `confirmed`, or `possible`.

`milestones` always has `csr`, `issuance`, `installation`, `activation`, and
`live_tls`. Each value is `not_attempted`, `confirmed`, `failed`, `uncertain`, or
`not_applicable`. A milestone is confirmed only from worker-visible validation
or a validated success response. The aggregate chooses the first target at
highest severity: `failure_ambiguous` > `failure_partial` >
`failure_pre_attempt` > `attention_due` > `success_changed` >
`success_prepared` > `success_no_change`. For attention or failure the top-level
stage, reason, and message come from that target. For success the top-level
stage is `completed`; recovery is the OR of global and target flags.

## UniFi evidence and exits

Shared `inspect` checks the current public keystore certificate, expected key
continuity, and expiry threshold. It does not establish CA trust,
SAN/hostname validity, fresh live TLS, or exact live certificate deployment.
A due or expired leaf produces `attention_due`, `renewal_due: true`, and
exit 0. Legacy `inspect` output and exit remain unchanged. `csr` success
confirms only the validated CSR, with `change: none`. `prepare` succeeds as
`sign_csr` with CSR and issuance confirmed and no UniFi import. A not-due
`renew` is `success_no_change`, `renewal_due: false`, with no signing or import.
Completed `install` and due `renew` confirm all five milestones only after the
executor returns a valid `renewal_finalized` result.

Issuance becomes uncertain immediately before the OPNsense signing HTTP
transport call. A valid saved response and UUID confirm it even if later public
leaf retrieval fails. Installation becomes uncertain immediately before the
first state-changing executor socket write. Local validation, socket identity,
or connection failures before that write retain prior evidence. A successful
install response alone does not confirm activation: the executor restores the
initial service state, which may be stopped. The worker confirms installation
after its post-import validation; it confirms activation and live TLS only after
validated `renewal_finalized` completion. Generic executor rejection and lost
responses remain uncertain. The worker does not read the privileged journal.
Executor startup recovery lies outside this worker result.

A handled failure before a certificate-related change is `failure_pre_attempt`.
A confirmed change with no later uncertain operation is `failure_partial`.
A dispatched state-changing operation with unresolved effect is
`failure_ambiguous`. `manual_recovery_required` is independent of outcome and
is true when signing may have occurred, issuance is confirmed but the requested
operation is incomplete, executor installation or verification may have run, or
blind retry cannot be proven safe. Ordinary configuration and application lock
failures need no manual recovery. Application lock busy produces one result,
`reason_code: "lock_busy"`, and exit 75. The external host `flock` can prevent
the worker from starting; its exit 75 has no attempt ID or result document.

The legacy exit is preserved: success and inspect attention exit 0, handled
failures exit 1, and application busy exits 75. Shared results exclude
credentials, exception text, child diagnostics, CSR/PEM material, subject,
SANs, issuer, serial, public key, host/IP, socket and filesystem paths, journal
details, and executor transaction IDs. Schema-v1 closed enums must not gain
values without a new schema version.
