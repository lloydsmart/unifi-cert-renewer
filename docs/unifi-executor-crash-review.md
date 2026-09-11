# Executor crash-boundary review

This is a protocol analysis of the disabled executor foundation, not power-loss
test evidence. `J` denotes the journal, `N` its temporary replacement, `S` stage,
and `R` rollback. The lock may exist at every boundary and is never removed.
Old canonical content is assumed valid at entry. Service state describes the
existing container; after container/host restart it is unknown until a startup
hook enforces exclusion. See [executor assumptions](unifi-executor.md).

Every journal update can leave the previous journal plus a partial/complete `N`
before replacement, or the previous/new journal before directory fsync. Recovery
uses the surviving validated journal and fresh public/inode checks; a malformed
journal or unexpected artifact fails closed. Successful fsync is assumed honored
by storage. An exception after a successful syscall has the same disk ambiguity
as an interruption at that point; an in-memory phase is not durable evidence.

* **Before first journal creation.** Files/journal: Lock only. Canonical/rollback: Old; no R.
  Service/recovery: Untouched; no active transaction.

* **During initial journal creation.** Files/journal: N, possibly J. Canonical/rollback: Old; no R.
  Service/recovery: Untouched; lone N needs operator.

* **After initial journal is durable.** Files/journal: J: quiescing. Canonical/rollback: Old; no R.
  Service/recovery: Initially running or down; quiesce, verify old, restore initial state.

* **During or after service stop.** Files/journal: J: quiescing/quiesced. Canonical/rollback: Old;
  no R. Service/recovery: Stopping/down; recovery proves no writers before inspecting.

* **During stage creation/copy.** Files/journal: J: staging; S absent/partial. Canonical/rollback:
  Old; no R. Service/recovery: Down; verify old and clean safe S; incomplete ownership needs
  operator.

* **After stage copy.** Files/journal: J: staging; S old, inode may not yet be recorded.
  Canonical/rollback: Old; no R. Service/recovery: Down; verify old, clean S, restore service.

* **During keytool mutation.** Files/journal: J: staging; S old/partial/issued. Canonical/rollback:
  Old; no R. Service/recovery: Down; inherited lock excludes recovery until child exits; then
  recover old.

* **After keytool, before validation.** Files/journal: J: staging; S untrusted. Canonical/rollback:
  Old; no R. Service/recovery: Down; discard safe S only after proving old.

* **After stage validation, before fsync.** Files/journal: J: staging; S validated in memory only.
  Canonical/rollback: Old; no R. Service/recovery: Down; recover old, never commit S during
  recovery.

* **After stage fsync.** Files/journal: J: staging/staged_validated; S synced. Canonical/rollback:
  Old; no R. Service/recovery: Down; recover old.

* **After old canonical fsync.** Files/journal: J: staged_validated; S synced. Canonical/rollback:
  Old synced; no R. Service/recovery: Down; recover old.

* **After hard link, before directory fsync.** Files/journal: J: staged_validated; R may survive.
  Canonical/rollback: Old synced; R not yet durably guaranteed. Service/recovery: Down; validate any
  surviving R, recover old.

* **After rollback directory fsync.** Files/journal: J: staged_validated/rollback_durable.
  Canonical/rollback: Old; R durably retains old inode. Service/recovery: Down; validate R even if
  journal flag lags, recover old.

* **Before rename.** Files/journal: J: commit_possible; S and R synced. Canonical/rollback: Old; R
  durable. Service/recovery: Down; old recovery; never retry commit.

* **After rename, before directory fsync.** Files/journal: J: commit_possible; namespace durability
  uncertain. Canonical/rollback: Old or issued after crash replay; R durable. Service/recovery:
  Down; inspect identities/public state to choose old or issued; otherwise stop.

* **After post-rename directory fsync.** Files/journal: J: commit_possible/committed; R.
  Canonical/rollback: Issued namespace durable; R durable. Service/recovery: Down; verify issued and
  R, retain R for Stage 7.

* **During canonical verification.** Files/journal: J: committed; R. Canonical/rollback: Issued, or
  corruption detected; R old. Service/recovery: Down; issued resumes with R; unreadable expected
  canonical may restore R.

* **After canonical verification.** Files/journal: J: committed/canonical_verified; R.
  Canonical/rollback: Issued; R old. Service/recovery: Down; recovery repeats public verification.

* **During service restart.** Files/journal: J: canonical_verified; R. Canonical/rollback: Issued; R
  old. Service/recovery: Possibly running; recovery stops and checks it again.

* **After restart, before journal update.** Files/journal: J: canonical_verified or new pending
  phase; R. Canonical/rollback: Issued unless writer changed it; R old. Service/recovery: Running if
  initially running; fresh exclusion and verification required.

* **After pending-live phase.** Files/journal: J: service_resumed_pending_live_verification; R.
  Canonical/rollback: Issued; R retained. Service/recovery: Initial service state restored; Stage 7
  still outstanding. A fresh process does not infer prior external verification.

* **After TLS success, before durable journal update.** Files/journal: J may read
  service_resumed_pending_live_verification or live_verified if replacement
  occurred before directory fsync; R. Canonical/rollback: Issued; R old.
  Service/recovery: Pending requires fresh TLS verification. Readable live_verified
  requires a fresh journal-file and directory durability barrier before cleanup.
  Barrier failure retains R.

* **After `live_verified` is durable.** Files/journal: J: live_verified; R.
  Canonical/rollback: Issued; R old. Service/recovery: External success is known;
  re-establish the durability barrier, validate fixed public/file identities, and
  continue cleanup without signing or import.

* **During rollback cleanup.** Files/journal: J: live_verified; R present or absent.
  Canonical/rollback: Issued; R old if present. Service/recovery: Repeat unlink and
  directory sync idempotently; absence is accepted only because J is live_verified.

* **After rollback sync, during journal cleanup.** Files/journal: J: live_verified
  or absent; no R. Canonical/rollback: Issued; no R. Service/recovery: Remove J and
  sync, or if J is already absent complete the final directory sync. Never mutate
  the keystore or repeat import.

* **During recovery rename.** Files/journal: Previous J; R may become canonical. Canonical/rollback:
  Old or previous canonical; no two-rename gap. Service/recovery: Down; repeated recovery verifies
  whichever namespace survived.

* **During old-state cleanup.** Files/journal: J: recovered_old; S/R/N may remain.
  Canonical/rollback: Verified old canonical; R may be gone. Service/recovery: Initial service state
  restored; repeat verification/cleanup.

SIGTERM's default action and SIGKILL do not execute Python `finally` cleanup.
Within the same container, s6's down intent remains but there is no helper
supervisor here to recover automatically. Surviving children inherit the flock;
recovery also checks actual processes, including deleted executable names.
Container/Docker restart and host reboot may restart UniFi before this library
runs; a journal alone does not prevent that. Remounts can additionally invalidate
the device identities as described in the executor documentation. These are
deployment blockers, not guarantees supplied by the callable recovery method.

Recovery distinguishes old and issued public chains/SPKI and recorded inode
identity without exporting private material. It cannot prove possession merely
from those public observations. It never deletes the canonical path. Cleanup
follows proven old-state recovery or durable `live_verified` state; unverified
issued-state recovery retains R. A valid canonical with an invalid R, two
invalid copies, a missing required R before live verification, an
unexpected valid same-key certificate, or changed inode requires an operator.
Under the documented writer exclusion, no reviewed cleanup path destroys the
only proven valid keystore. Concurrent unexcluded namespace/content changes or
storage that does not honor fsync invalidate that conclusion.

The tests include 25 actual SIGKILL checkpoints in forked disposable helpers,
covering initial journal creation, service stop, copy/import, file/directory
fsync, rollback link, rename, canonical verification, service resume, durable
live verification, and finalisation cleanup. These tests bypass Python cleanup
but retain the kernel and its page cache. They use simulated s6 and public-state
markers, not a real service or host power failure.
Separate generated-keystore OpenJDK tests exercise actual import and public
verification. Neither test group establishes power-loss guarantees.
