# Key-owner-local executor and recovery

## Production boundary

`ProductionUnifiExecutor` executes **inside the UniFi environment**, not inside
the renewer. `SocketUnifiExecutionBoundary` connects from the renewer through
the fixed `/run/unifi-cert-renewer/executor.sock`. This is an AF_UNIX socket,
not a network listener. Protocol version 1 supports exactly `inspect`,
`generate_csr`, `install`, `recover`, and `finalize`.

Requests are strictly shaped JSON behind a four-byte length prefix and have an
8 MiB upper bound. One absolute monotonic deadline spans header and body reads;
each socket timeout is capped to its remaining budget. Public binary values use
validated base64. Unknown/duplicate fields, operations, malformed encodings,
and oversized messages fail. There is no generic dispatch and no request field
for a path, alias, service, executable, argv, password, transaction ID, Python
callable, or success Boolean. Responses contain normalized public state, a
public CSR, or a fixed outcome. Errors use a single bounded diagnostic and never
reflect request or child-process data. Disconnects and response write failures
are connection-local. An operation that has started runs through its executor
state transition before the server attempts to return its response.

The renewer-side adapter preserves the existing `UnifiClient` interface. For an
installation, the server performs the complete shared client validation and
exclusive transaction locally, then returns normalized public post-state already
proved equal to the issued chain. The renewer independently repeats the existing
post-import check against that public result. No lock or partially completed
mutation session is delegated across the socket.

The root-owned socket directory must be exactly mode `0750`; the root-owned
socket is mode `0660` and uses the directory's group. Only the dedicated group
assigned by the host operator can traverse the directory and connect. Both ends
validate these properties and socket identity. Missing or unsafe prerequisites
fail closed. Socket bind uses a restrictive publication umask. Under the
listener lock, restart removes only a root-owned socket with the exact published
mode, directory device and either the pre-chown root group or final dedicated
group; wrong-type, wrong-owner, wrong-mode, linked, or replaced entries fail
closed. Host root remains trusted and controls group membership.

The reviewed baseline requires local root for the narrowly scoped helper, `abc`
uid/gid `1000:1000`, Linux `/proc`, s6, and `/usr/bin/keytool`. Appdata may use
Btrfs, XFS, ZFS, ext4, or another normal local filesystem. This does not require
a root renewer or a Docker socket. The helper's root privilege is confined by its
fixed operation interface, not by claiming that its Python process is sandboxed
from other container files.

Host root is trusted. Exclusion covers UniFi, project-controlled helpers, and
cooperating writers, not a malicious privileged administrator. All other
project-controlled automation must use the same lock. Container initialization
and host maintenance must not overlap an active transaction. The helper must
have a complete process namespace. Normal LinuxServer cross-UID restrictions on
`/proc/<abc-pid>/exe` are handled by a fixed, short-lived inspection child that
drops irreversibly to uid/gid `1000:1000`; `CAP_SYS_PTRACE` is not required. A
host that prevents even this same-UID inspection is unsupported and fails
closed.

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
Each numeric proc directory is opened once and subsequent identity reads are
relative to that descriptor. Root-visible processes retain the direct path. A
permission-denied process uses the same-UID child only after proc ownership and
all real/effective/saved/filesystem UID and GID values prove the fixed
`1000:1000` identity. The child closes unrelated descriptors, clears
supplementary groups, sets all GIDs and UIDs to 1000, verifies the drop, and
returns one bounded classification byte through a pipe before exiting. The
parent bounds the wait and always reaps it, then rechecks the anchored identity.
Drop, IPC, timeout, ownership, or identity ambiguity fails closed. Both the
`exe` link and bounded `cmdline` remain mandatory; there is no command-line-only
fallback.
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
A replacement may be readable before its directory fsync has completed; recovery
never treats readability alone as proof of transition durability.

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
| `live_verified` | Exact external TLS success recorded; re-establish its durability barrier before cleanup |
| `recovery_required` | Failed/interrupted attempt; inspect fresh state |
| `recovered_old` | Old state verified and initial service state restored; cleanup may be incomplete |

The mutation sequence is stage-only import, exact public validation, stage fsync,
canonical fsync, rollback hard link, directory fsync, durable commit intent,
atomic stage-over-canonical replacement, directory fsync, fresh canonical
verification, client verification, and service restoration. Canonical never
undergoes a two-rename gap. File identities are checked again around commit.
A success message from keytool is never an acceptance criterion.

## Stage 7 live verification and finalisation

The application side owns endpoint verification. `LiveTLSEndpoint` separately
configures a numeric network address, port, and TLS server identity; none is
hard-coded. Requiring a numeric connection address prevents DNS resolution from
escaping the readiness deadline; the server identity may still be a DNS name.
A fresh socket is opened after Stage 6 has restored the service. Python's normal
verified client context performs chain and hostname authentication against the
explicit public CA with TLS 1.2 as the minimum. Only after that succeeds is the
peer leaf retrieved and compared byte-for-byte in canonical DER form with the
issued leaf. Subject, SAN, issuer, serial, validity, CA membership, or SPKI alone
cannot satisfy this check.

Readiness is bounded by an absolute monotonic deadline, a maximum attempt count,
per-attempt timeout, and bounded delay. Pre-authentication refusal, reset, and
timeout may retry. TLS authentication or protocol failure and an authenticated
wrong leaf fail without being treated as ordinary readiness.

The key-owner-side `finalize_live_verification()` operation accepts only the
canonical public DER leaf. It requires a journal in
`service_resumed_pending_live_verification`, the expected service-running state,
the exact pending issued-leaf SHA-256, the committed inode/public chain, and the
old rollback inode/public state. A Boolean assertion, arbitrary transaction ID,
path, command, or executable cannot be supplied.

The executor writes and fsyncs `live_verified` before removing anything. Before
every initial, repeated, or recovery cleanup path, it fsyncs the journal file,
checks its fixed identity, fsyncs the containing directory, and checks identity
again under the transaction lock. This re-establishes the namespace durability
barrier if an earlier process exposed the replacement but failed before its
directory fsync. Barrier failure retains rollback and fails closed.

Only after that barrier does the executor unlink rollback, fsync the containing
directory, remove the journal, and fsync again. If external verification succeeds
but no `live_verified` journal replacement is visible, the earlier pending state
and rollback remain authoritative and a later caller must verify live TLS again.
A readable `live_verified` record authorizes recovery only after the fresh
barrier succeeds. Missing rollback is accepted only in that phase, covering an
interrupted unlink. Cleanup also requires single-link canonical and rollback
keystores and rejects any surviving stage or temporary journal, because none of
those namespace states is reachable after a valid transition. A crash after
journal removal is recovered as no active transaction; recovery issues a final
directory sync, and no mutation is repeated.

## Startup and explicit recovery

A supplied s6 oneshot invokes startup recovery before LinuxServer's UniFi
configuration init. That init depends on the recovery decision. Before opening
the strict executor, the oneshot repairs the exact interrupted-normalization
case: only fixed lock/journal entries may transition from the expected `abc`
ownership back to root, under the executor lock, after type, mode, size,
link-count, no-follow, journal-schema, reachable phase/flag/artifact, and
recorded transaction-inode checks. Transaction evidence without the persistent
lock is never repaired by creating a replacement lock. All entries are proved
before the first ownership change. A crash between fixed files leaves a
root/`abc` mixture that the next boot revalidates and completes.
An incomplete temporary journal may be normalized only beside a durable phase
that can perform or retry another journal write. It is rejected beside
`live_verified`, where the publishing rename already consumed the temporary
name and only durability checks and cleanup remain.
Because LinuxServer init recursively assigns appdata to `abc`, a second fixed
oneshot repeats the same normalization and recovery inspection against the
post-init state. Both Java and the executor socket depend on this second
oneshot. The startup recovery mode deliberately leaves Java down; s6 starts it
only after both oneshots succeed.

Absence of recovery state permits normal startup. Known old or issued state is
recovered using the existing state machine. Corrupt, ambiguous, unsupported, or
mismatched identity blocks the oneshot and therefore Java. Repeated starts are
idempotent.
Recovery holds the normal transaction lock and never signs, imports, or creates
a missing keystore. After SIGKILL/container/host failure, on-disk state is
authoritative.

Automatic recovery is limited to matching recorded runtime device/inode
identities on every filesystem. These are not persistent filesystem IDs. Btrfs
is detected explicitly because subvolume roots use anonymous device numbers,
which can change after remount/reboot. Recovery then retains evidence and
requires operator intervention even when content appears intact. It never
ignores or rewrites a mismatch. The same conservative rule applies to any
filesystem whose recorded runtime identity cannot be proved.

| Observation | Decision |
| --- | --- |
| Canonical proves old state/inode | Restore service; durably clean artifacts |
| Canonical proves issued state/inode; rollback proves old | Resume; retain rollback/journal for Stage 7 |
| `live_verified`; issued canonical; rollback old/absent | Finish cleanup; report finalised recovery |
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

An operator-required result keeps startup blocked and emits only a bounded
diagnostic. The supervisor does not retry import. Neither a Docker socket nor a
general remote command endpoint is used.

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
storage firmware failure, or privileged hostile mutation. Filesystem durability
assumes the local filesystem and storage honor successful fsync calls.
Public-state checks do not extract private keys to test possession;
existing PrivateKeyEntry structure, CSR proof-of-possession, staged import and
exact public-key continuity provide the available evidence.

Deployment authentication and startup recovery integration are implemented by
the fixed Unix socket and s6 dependency overlay. Stage 7 is implemented in
source and tests, including real disposable loopback TLS servers. Generated TLS
server keys in tests are loaded through Linux memory-backed file descriptors and
never receive a filesystem pathname. Persistent recovery identity across an
ambiguous remount/reboot remains an intentional operator-recovery case.
Threshold renewal, general renewer-container packaging, scheduling, and key
rotation remain later work.
