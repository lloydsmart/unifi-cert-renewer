# Production executor deployment

## Topology and trust boundary

Build the executor overlay from the repository root:

```bash
docker build -f deployment/unifi/Dockerfile \
  --build-arg UNIFI_IMAGE=lscr.io/linuxserver/unifi-network-application@sha256:<reviewed-digest> \
  -t local/unifi-network-application-cert-renewer:reviewed .
```

Use that image in place of the otherwise identical LinuxServer UniFi image. The
overlay installs the executor source, its hash-locked dependency, and native s6
service definitions. The separate renewer image is described below.
Record and review the upstream image digest rather than building production from
a mutable tag. The repository's deny-by-default `.dockerignore` keeps unrelated
workspace files, Git data, local secrets, and certificate/keystore artifacts out
of the Docker build context.

After the image passes the deployment checks, record its registry digest and
deploy that exact derivative digest rather than its build tag:

```bash
docker image inspect --format '{{index .RepoDigests 0}}' \
  local/unifi-network-application-cert-renewer:reviewed
```

If the image has not yet been pushed to a registry, the local image ID is useful
build evidence but is not a portable deployment reference. Push through the
normal controlled release path, record the resulting digest, and use that digest
for the supervised deployment.

Create one host runtime directory using a dedicated unused numeric group ID:

```bash
install -d -o root -g 984 -m 0750 /run/unifi-cert-renewer
```

Bind-mount that directory at `/run/unifi-cert-renewer` in both the UniFi and
renewer containers. Add only the renewer process to supplemental group `984`.
Do not mount `/config`, the UniFi password secret, or `/var/run/docker.sock` into
the renewer. Keep `/run/secrets/unifi-keystore-password` mounted only in UniFi,
owned by root and mode `0600` as required by the existing secret-file policy.

The executor creates `executor.sock` as `root:984`, mode `0660`. Directory
search plus socket write permission is the authorization boundary: any process
in group `984` can invoke the five fixed operations, so no unrelated process may
join that group. A network client cannot connect because there is no IP listener.
If the directory is absent, symlinked, not root-owned, or not exactly `0750`, or
the socket has unsafe ownership/type/mode, the client/server fails closed.

The numeric group is deployment metadata, not a secret. Production currently
uses `984`; configure it consistently on the host and both containers. Do not
add unrelated processes to this group.

## Unprivileged renewer image

Build the renewer from the repository root:

```bash
docker build -f deployment/renewer/Dockerfile \
  -t local/unifi-cert-renewer:reviewed .
```

The Dockerfile pins the reviewed multi-platform manifest for the minimal
official `python:3.12-slim-bookworm` base and installs the hash-locked runtime
requirements. If that pin is intentionally updated, review the new upstream
image and record the replacement digest. After pushing the reviewed image,
deploy its registry digest rather than the local tag.

The image runs as uid/gid `1000:1000`. It packages only renewer orchestration,
certificate/CSR/TLS code, the OPNsense client, and the client half of the fixed
executor protocol. It does not contain the privileged executor, keystore file
operations, UniFi process control, or recovery implementation.

[`deployment/renewer/compose.example.yaml`](../deployment/renewer/compose.example.yaml)
is the production-shape example. Set `RENEWER_IMAGE` to the reviewed registry
digest and `RENEWER_SECRETS_DIRECTORY` to the host directory described below.
The service is read-only, drops every capability, enables
`no-new-privileges`, has no restart policy, and receives only:

- `/run/unifi-cert-renewer` at the same path, read-only, for the Unix socket;
- supplemental gid `984`; and
- its own read-only `/run/secrets` configuration and OPNsense credentials.

It does not receive UniFi `/config`, the UniFi keystore-password secret, or the
Docker socket. These omissions are part of the trust boundary, not deployment
options.

Create a dedicated secrets directory that the container can search without
making it writable. One suitable ownership model is a root-owned directory with
group `1000`, mode `0750`; root-owned public files mode `0444`; and the two API
credential files owned by uid `1000`, mode `0400`. The secure-file checks reject
symlinks, unsafe ownership, group/world-writable files, and group/world-readable
API credentials.

The fixed files are:

| File | Purpose | Private |
| --- | --- | --- |
| `renewer-config.json` | Strict public production configuration | No |
| `opnsense-api-key` | OPNsense API key | Yes, mode `0400` |
| `opnsense-api-secret` | OPNsense API secret | Yes, mode `0400` |
| Configured `trusted_ca_name` | Public issuing CA certificate | No |
| Configured `opnsense.tls_ca_name` | Optional public OPNsense HTTPS CA | No |

Start from
[`renewer-config.example.json`](../deployment/renewer/renewer-config.example.json),
replace every example identity and fingerprint, and keep the exact JSON field
set. `live_tls.address` must be a numeric address; `server_hostname` is the
independently verified DNS or IP identity. Arbitrary paths, aliases, commands,
executables, services, and socket paths are not configurable.

Before use, inspect the resolved Compose definition and image identity:

```bash
docker compose -f deployment/renewer/compose.example.yaml config
docker image inspect --format '{{.Config.User}}' "$RENEWER_IMAGE"
```

The expected image user is `1000:1000`. The resolved definition must show gid
`984` and only the runtime and renewer-secrets mounts. It must not show
`/config`, `unifi-keystore-password`, or `/var/run/docker.sock`.

## s6 startup ordering

The derivative image adds `init-unifi-cert-renewer-recovery` after LinuxServer's
`init-config` milestone but before `init-unifi-network-application-config`.
LinuxServer's configuration init depends on successful recovery. The recovery
oneshot first handles a narrowly validated partial ownership change left by an
interrupted previous LinuxServer initialization, then runs strict recovery. A
second fixed oneshot repeats ownership normalization and recovery after the
current init. Both the UniFi Java longrun and executor socket longrun depend on
that second oneshot. This prevents initialization or Java startup from racing
recovery evidence while retaining LinuxServer's required initialization
behavior.

The recovery oneshot uses the normal executor lock. With no transaction it
returns immediately. With provable old or issued state it recovers without
signing or importing and leaves Java down for s6 to start. Each ownership pass
accepts only the exact fixed regular admin files with mode `0600` and expected
root/`abc` ownership. A primary journal must be structurally valid and its
phase/flags, artifacts, and canonical/stage/rollback inode relationships must
represent a reachable transaction state before any chown. Transaction evidence
without the existing persistent lock is rejected; the pass does not create a
replacement lock beside it. The pass restores `root:root`, fsyncs files and
directory, and rejects symlinks, replacement, or unexpected state. Corrupt,
ambiguous, unsupported, or identity-mismatched state returns nonzero and blocks
dependent services. Repeated or partially completed ownership passes converge
safely.

The executor's fixed local prerequisites remain Linux `/proc`, root inside the
UniFi container, `abc` as uid/gid `1000:1000`, `/usr/bin/keytool`, the LinuxServer
service at `/run/service/svc-unifi-network-application`, and the existing fixed
`/config/data/keystore` alias `unifi`. Root does not need permission to resolve
`/proc/<abc-pid>/exe`: the executor internally uses a short-lived child fixed to
the verified `abc` identity for that case. `CAP_SYS_PTRACE` is not required.
Hosts that prevent this fixed same-UID inspection still fail closed. Executable
identity and bounded command-line inspection are both required.

## Renewer configuration

Construct the production UniFi client with:

```python
from unifi_client import UnifiClient
from unifi_executor_service import SocketUnifiExecutionBoundary

unifi = UnifiClient(SocketUnifiExecutionBoundary())
```

No socket path or privileged target is configurable. The caller can provide only
the existing public certificate policy and public renewal material. Protocol
version 1 exposes `inspect`, `generate_csr`, `install`, `recover`, and `finalize`.

The production entrypoint accepts exactly one of four manual one-shot modes:

```bash
docker compose -f deployment/renewer/compose.example.yaml run --rm renewer inspect
docker compose -f deployment/renewer/compose.example.yaml run --rm renewer csr
docker compose -f deployment/renewer/compose.example.yaml run --rm renewer prepare
docker compose -f deployment/renewer/compose.example.yaml run --rm renewer install
```

`inspect` returns validated public certificate metadata. `csr` generates a CSR
inside the UniFi key-owning environment and returns validated public identity,
key, and proof-of-possession metadata. `prepare` performs a fresh inspection and
CSR, signs through OPNsense, validates the issued leaf and import plan, then
exits without changing UniFi. `prepare` is state-changing on OPNsense because it
issues a certificate, but it does not mutate UniFi. Because no transaction
material is persisted in the stateless renewer, a later `install` starts a new
transaction and obtains a freshly signed certificate. `install` is the sole
UniFi-mutating one-shot mode: it performs the complete sequence once, requires
configured live TLS verification, and reports `renewal_complete` only after
exact live-leaf verification and executor finalisation.

There is no cron entry, scheduler loop, daemon, threshold policy, automatic
state-changing retry, or container restart loop. After any ambiguous signing,
installation, verification, or finalisation failure, stop and inspect the
recorded state; do not automatically invoke the mode again.

## Filesystem behavior

Btrfs is not required. Every normal local filesystem follows the same generic
transaction path: fixed dirfd-relative names, no-follow opens, owner/mode/type/
link-count checks, live device/inode checks, an independent stage, rollback hard
link, atomic same-directory replacement, file/directory fsync ordering, durable
journal, and conservative recovery.

Btrfs detection remains explicit because its subvolume `st_dev` can be an
anonymous runtime number. Runtime device/inode identity is deliberately not
treated as persistent on any filesystem. If remount/reboot makes recorded
identity ambiguous, startup blocks and preserves evidence for an operator. Do
not edit the journal or delete rollback artifacts merely to make startup pass.

Threshold policy and unattended scheduling are not implemented by issue #17.

## Disposable boot evidence

The issue #17 review fixes were exercised on 2026-09-12 using LinuxServer
`10.6.101-ls145` from upstream digest
`sha256:ccadcad5c640c91388d79e66a3751e4de3c9accdcef181f76c142aeca612214d`.
The candidate derivative was built with hash-verified offline wheels as local
image ID
`sha256:6e02a4b80e69e60026d38e24a5e764ac35425d4c31482c57ec9f3a7c0930d330`.
This local ID is build evidence, not the registry digest required for deployment.

A real `/init` boot used isolated disposable configuration/runtime mounts and a
reachability-only test database listener. Logs showed pre-recovery, LinuxServer
configuration and disposable keystore generation, post-init normalization and
recovery, then Java and executor eligibility in that order. Final state was a
`root:root` mode `0600` executor lock and `root:<dedicated-group>` mode `0660`
socket. A corrupt `abc`-owned journal made the pre-recovery service exit nonzero;
neither Java nor the executor process started. A following boot with only an
`abc`-owned persistent lock and the stale socket entry repaired the lock,
removed/replaced the recognized socket safely, and again reached Java/executor
eligibility. No production keystore, production credentials, external network,
or production appdata was used.

This Docker host denied container root permission to resolve
`/proc/<abc-java-pid>/exe` after Java started. Issue #19 adds fixed same-UID
inspection for this normal LinuxServer topology without `CAP_SYS_PTRACE`. The
root executor first proves the anchored process directory and all UID/GID status
values are `1000:1000`; only then does a short-lived, irreversibly dropped child
inspect both `exe` and bounded `cmdline`. Other inaccessible identities, failed
drops, ambiguous identity changes, and hosts that deny same-UID inspection fail
closed.

After deploying the merged image on Tower, the following read-only preflight
checks the observed restriction, the same-UID visibility, and the executor's
complete classification. Replace `unifi` only if the container has a different
operator-assigned name:

```bash
docker exec -u 0 unifi sh -c \
  'pid="$(pgrep -o -f "/usr/lib/unifi/lib/ace.jar start")"; readlink "/proc/$pid/exe"'
docker exec -u 0 unifi s6-setuidgid abc sh -c \
  'pid="$(pgrep -o -f "/usr/lib/unifi/lib/ace.jar start")"; readlink "/proc/$pid/exe"'
docker exec -u 0 unifi env PYTHONPATH=/opt/unifi-cert-renewer/src \
  /opt/unifi-cert-renewer/venv/bin/python -c \
  'from unifi_process import _processes; print(_processes())'
```

On the affected topology the first command reports permission denied, the
second prints the Java executable target, and the third prints `(True, False)`.
These commands do not request a CSR, sign, install, restart UniFi, or access
private-key material.

The pinned Trivy `0.74.0` scan reported 31 fixable findings (6 CRITICAL and 25
HIGH) in the exact reviewed upstream UniFi image: 23 in upstream Java libraries
and 8 in its `pebble` binary. Comparison against that exact upstream is required.
HIGH/CRITICAL findings introduced by the derivative are blockers. Findings
inherited unchanged from the exact reviewed upstream are not automatically
blockers unless review shows that they materially undermine the executor or
keystore trust boundary. Record both the comparison and that impact review; do
not suppress or silently discard inherited findings.
