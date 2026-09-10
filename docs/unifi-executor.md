# Key-owner-local executor and recovery

## Deployment gate and trust boundary

`ProductionUnifiExecutor` is code for execution **inside the UniFi environment**,
not inside the renewer. It has no remote server, CLI, Docker interface, or
production enablement option. `_require_mutation_review()` always raises for
installation and recovery. Tests replace this private gate only for disposable
files and simulated service control. Removing the gate requires reviewed code
and deployment design; unattended production mutation remains unsupported.

The reviewed baseline currently requires local root for the narrowly scoped
helper, `abc` uid/gid `1000:1000`, Linux `/proc`, s6, `/usr/bin/keytool`, and Btrfs
appdata. Other ownership/filesystem layouts fail closed. This does not require
a root renewer or a Docker socket. The helper's root privilege is confined by its
operation interface, not by claiming that its Python process is sandboxed from
other container files. A future transport must authenticate and authorize callers
and must not expose private helper methods or arbitrary Python invocation.

Host root is trusted. Exclusion covers UniFi, project-controlled helpers, and
cooperating writers, not a malicious privileged administrator. All other
project-controlled automation must use the same lock. Container initialization
and host maintenance must not overlap an active transaction. The helper must
have a complete, readable process namespace; restricted `/proc` is unsupported.

This exclusion assumption also covers other processes running as `abc`.
Root ownership of a journal or lock does not prevent their removal from an
`abc`-writable directory. Supporting active, noncooperating processes with that
directory's write privileges would require a reviewed protected namespace and
writer boundary.

## Fixed files and collection

All transaction entries are adjacent beneath `/config/data`:

| Entry | Ownership/mode | Purpose |
| --- | --- | --- |
| `keystore` | `abc:abc`, `0600` | Existing canonical PKCS12 |
| `.cert-renewer-stage` | `abc:abc`, `0600` | Independent working inode |
| `.cert-renewer-rollback` | `abc:abc`, `0600` | Hard link retaining old inode |
| `.cert-renewer-lock` | `root:root`, `0600` | Persistent cooperating-writer flock |
| `.cert-renewer-journal` | `root:root`, `0600` | Public-only recovery state |
| `.cert-renewer-journal-new` | `root:root`, `0600` | Atomic journal update temporary |

The lock is never unlinked. Directory components are opened with `O_NOFOLLOW`
and checked for trusted ownership and no group/other write access. File opens
are dirfd-relative, nonblocking and no-follow; creations are exclusive. Regular
file type, exact mode/owner, device, size bounds and link counts are checked.
Fresh device/inode/size/mode/uid/gid/mtime/ctime/link-count comparisons surround
collection, staging and commit. No caller selects a pathname. Whole keystores
are copied kernel-to-kernel with `copy_file_range`; no Python private-key parsing,
keystore hashing, or standalone private-key output occurs.

A single bounded `keytool -list -rfc` invocation collects global metadata and
complete public chains. The collector selects exactly alias `unifi`, validates
PKCS12/SUN/PrivateKeyEntry and chain length, parses public DER, and returns only
normalized metadata and public certificates. It checks file identity before and
after collection under the helper lock. Output from unrelated aliases is bounded
but not returned. Very large multi-alias stores exceeding the output bound fail.
Read-only inspection/CSR operations do not stop UniFi; observable concurrent
changes fail their identity checks. Active recovery state blocks these standalone
operations; explicit recovery performs fresh inspection under service exclusion.

## Child and service lifecycle

Commands use argument arrays with `shell=False`, an isolated process session,
fixed executables, a minimal environment, bounded stdin and separate bounded
stdout/stderr capture (1 MiB each), and a 30-second deadline. Raw diagnostics are
never returned or logged. The password is loaded locally from the fixed secret
file `/run/secrets/unifi-keystore-password`, at most 4096 bytes, and supplied only
as `UNIFI_KEYSTORE_PASSWORD` to keytool. It is never in argv or public results.

On failure/cancellation, the runner sends TERM, waits up to two seconds, sends
KILL to the process group, and reaps the child before releasing exclusion. An
uninterruptible kernel task can delay reap; safety takes priority over returning
while a writer lives. The flock FD is inherited by children: abrupt helper death
does not release exclusion while a child still holds it. Recovery additionally
rejects surviving keytool executables or Java keytool main processes. It does not
kill arbitrary pre-existing keytool processes or retry their operations.

`s6-svc -wD -T 25000 -d` quiesces the fixed
`/run/service/svc-unifi-network-application`. The helper checks stable s6 state
and positively scans actual executable/argv identity for
`java ... -jar /usr/lib/unifi/lib/ace.jar start`; shell text does not match.
Resume uses `-wU -T 25000 -u` and checks readiness and the actual JVM. Initially
down services remain down. Canonical identity/public state are checked across
resume. Unexpected surviving/uninspectable writers retain the helper's lock;
operator intervention and helper exit are required before a new helper can
attempt recovery. A normal failure with no surviving writer releases the lock
but retains the journal and service-down intent.

## Durable state machine

The journal schema is bounded and rejects unknown fields, duplicate JSON keys,
invalid phases, fingerprints, booleans and inode identities. It contains only a
transaction UUID, version, phase, initial service-running intent, old/issued SPKI
and ordered certificate SHA-256 fingerprints, device/inode identities, and
rollback/commit flags. Fixed filenames are implicit in schema version 1.
No password, API credential, diagnostics or keystore bytes are included.

Each transition writes an exclusive temporary journal, fsyncs it, atomically
replaces the journal and fsyncs the directory. Journal presence blocks new work.

| Phase | Durable meaning / next action |
| --- | --- |
| No journal/artifacts | No active transaction |
| `quiescing` | Old public/inode identity and service intent saved before s6 down |
| `quiesced` | Service/JVM absent and fresh canonical equals pre-state |
| `staging` | Issued identity recorded; independent copy/import may be incomplete |
| `staged_validated` | Stage passed shared Stage-6 verification and file fsync |
| `rollback_durable` | Old hard link created and directory fsynced |
| `commit_possible` | Commit intent durable before atomic namespace replacement |
| `committed` | Replacement and directory fsync completed |
| `canonical_verified` | Fresh canonical passed shared Stage-6 verification |
| `service_resumed_pending_live_verification` | Initial service state restored; retain rollback/journal |
| `recovery_required` | Failed/interrupted attempt; inspect fresh state |
| `recovered_old` | Old state verified and initial service state restored; cleanup may be incomplete |

The mutation sequence is stage-only import, exact public validation, stage fsync,
canonical fsync, rollback hard link, directory fsync, durable commit intent,
atomic stage-over-canonical replacement, directory fsync, fresh canonical
verification, client verification, and service restoration. Canonical never
undergoes a two-rename gap. File identities are checked again around commit.
A success message from keytool is never an acceptance criterion.

## Explicit recovery

A deployment must invoke `recover()` on helper startup before accepting work,
and after failed attempts. The library supplies the gated recovery operation;
the supervisor/startup hook is not packaged yet. A `finally` block is not crash
recovery. After SIGKILL/container/host failure, on-disk state is authoritative.
Recovery acquires the lock, proves no keytool survives, validates the journal,
quiesces UniFi, checks protected files, and collects fresh public state.

Automatic recovery is limited to matching recorded device/inode identities.
The journal's `st_dev` values are **not persistent filesystem identifiers**:
Btrfs reports an anonymous device number allocated for an in-memory subvolume
root. A remount or reboot can change that number. Recovery then retains the
artifacts and requires operator intervention, even when their contents are
intact. It must not simply ignore the mismatch or rewrite the journal identity.
A reviewed persistent filesystem/subvolume identity design remains required
before enabling unattended recovery across remounts or host reboot. This follows
from the kernel's [Btrfs stat implementation][btrfs-stat] and
[anonymous device allocation][btrfs-device].

[btrfs-stat]: https://github.com/torvalds/linux/blob/master/fs/btrfs/inode.c
[btrfs-device]: https://github.com/torvalds/linux/blob/master/fs/btrfs/disk-io.c

| Observation | Decision |
| --- | --- |
| Canonical proves old state/inode | Restore service; durably clean artifacts |
| Canonical proves issued state/inode; rollback proves old | Resume; retain rollback/journal for Stage 7 |
| Canonical unreadable, expected inode; rollback proves old | If commit possible: restore, sync, verify, resume, clean |
| Missing/unsafe/unexpected canonical or rollback | Fail closed; operator intervention |
| Child/writer still alive or cannot be inspected | Retain exclusion; operator intervention |

A crash between commit and journal update is covered by `commit_possible` and
fresh public/inode comparisons. A rollback link created just before a journal
failure is also inspected rather than trusted from the phase alone. Corrupt
stages may be removed during completed old-state recovery only after safe file
and recorded inode checks. Issued-state recovery retains the rollback; it never
claims renewal complete. Recovery does not import, sign, generate a key, delete
an alias, or create a missing canonical keystore.

Some interrupted file creations also require operator intervention: a lone
initial `.cert-renewer-journal-new` without a journal, or a stage created before
its ownership/mode normalization completed. They are not silently deleted.
The former occurs before service stop; the latter can leave UniFi down.

The narrowest future integration is a fixed local startup/supervisor hook inside
the key-owning environment, ordered before UniFi initialization and s6 service
startup. It must also handle helper death while the container remains running,
serialize through the same lock, and run recovery before accepting new work.
An operator-required result must keep startup blocked and surface a diagnostic;
the supervisor must not retry import. A future invocation boundary must bind
authenticated semantic requests to locally authorized CA/identity policy.
Neither a Docker socket nor a general remote command endpoint is needed.

See the [crash-boundary review](unifi-executor-crash-review.md) for the durable
states, interruption outcomes, and limits of the available test evidence.

## Evidence, tests and remaining limits

[Issue #12](https://github.com/lloydsmart/unifi-cert-renewer/issues/12) records
OpenJDK 25.0.2 destructive writes, Btrfs inode/atomic rollback tests, and real s6
stop/start observations. Unit tests inject service/process/filesystem failures
and use real disposable files for link/rename/fsync ordering and recovery.
Optional Java tests use generated disposable PKCS12 files; they ran against
Temurin OpenJDK 25.0.4 during implementation. Run them with a local test JDK:

```bash
UNIFI_TEST_KEYTOOL=/path/to/test-jdk/bin/keytool .venv/bin/pytest -q
```

No production keystore was touched. Tests do not simulate actual host power loss,
storage firmware failure, privileged hostile mutation, or a production helper
supervisor. Filesystem durability assumes Btrfs and storage honoring successful
fsync calls. Public-state checks do not extract private keys to test possession;
existing PrivateKeyEntry structure, CSR proof-of-possession, staged import and
exact public-key continuity provide the available evidence.

Deployment authentication, startup recovery integration, and review of the
helper's privileges remain prerequisites to removing the gate. Stage 7 must
verify a fresh strictly validated TLS connection and exact issued leaf before
removing a committed rollback/journal. No live-success cleanup API is offered
until that verification is implemented.
