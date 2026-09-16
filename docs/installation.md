# Installation and operation runbook

This is the primary operator path for installing a released
`unifi-cert-renewer` deployment beside an existing LinuxServer UniFi Network
Application. It covers initial deployment, the first supervised renewal,
verification, upgrades, and failure handling.

This project provides threshold-based one-shot renewal but does not deploy an
unattended scheduler. An operator may invoke that mode from cron or Unraid User
Scripts after completing this supervised setup. For the security rationale and
full deployment contract, see
[Production deployment](production-deployment.md). For implementation details,
see [Certificate installation](certificate-installation.md) and
[Executor and recovery](unifi-executor.md). The recorded production
qualification is [Supervised production acceptance renewal](first-production-renewal.md).

## 1. Prerequisites and supported topology

The supported production topology has two containers:

1. The operator's existing LinuxServer UniFi Network Application deployment,
   migrated to the released derivative UniFi image. The derivative adds the
   privileged, fixed-operation executor and its s6 startup/recovery services.
2. A separate released renewer image. It runs as `1000:1000`, has no restart
   loop, and connects to the executor through a permission-controlled Unix
   socket.

UniFi retains its existing HTTPS private key. The private key and keystore never
enter the renewer. OPNsense retains the issuing CA private key. The renewer sends
only a public CSR and retrieves only the public issued certificate.

Before starting, have:

- a working LinuxServer UniFi Network Application whose existing `/config`,
  database configuration, networks, addresses, and environment are recorded;
- a protected backup/recovery reference for the existing UniFi appdata;
- an OPNsense administrator able to install the project ACL and create a
  dedicated API identity;
- an existing, directly issuing self-signed OPNsense CA supported by the current
  implementation;
- Docker with the Compose plugin on the deployment host;
- an operator-controlled Docker network shared by UniFi and the renewer, with a
  stable numeric address reserved for UniFi;
- the existing UniFi keystore password, provisioned as a secret file without
  printing it; and
- a supervised maintenance window in which an operator can observe UniFi stop,
  installation, restart, live verification, and finalisation.

The current executor contract also requires the LinuxServer `abc` identity to
be `1000:1000`, `/usr/bin/keytool`, the `unifi` PKCS12/SUN
`PrivateKeyEntry`, Linux `/proc`, and the expected LinuxServer s6 service layout.
Confirm these assumptions against the selected release and the deeper
[production deployment reference](production-deployment.md).

## 2. Select and verify a release

Production deployments must use both immutable registry references recorded on
one GitHub release. Never deploy a version tag, `latest`, or a locally rebuilt
image as an equivalent substitute for released content.

Open the chosen [GitHub release](https://github.com/lloydsmart/unifi-cert-renewer/releases)
and record its release tag, source commit, and the two complete image references.
The same information is available with GitHub CLI:

```bash
RELEASE_TAG='<chosen-release-tag>'
gh release view "$RELEASE_TAG" \
  --repo lloydsmart/unifi-cert-renewer
```

Populate these host-shell variables from that release. Do not copy the values
from historical evidence elsewhere in this repository:

```bash
SOURCE_REVISION='<40-character-release-source-commit>'
RENEWER_DIGEST='sha256:<renewer-release-digest>'
UNIFI_DIGEST='sha256:<unifi-derivative-release-digest>'
RENEWER_IMAGE="ghcr.io/lloydsmart/unifi-cert-renewer@${RENEWER_DIGEST}"
UNIFI_IMAGE="ghcr.io/lloydsmart/unifi-network-application-cert-renewer@${UNIFI_DIGEST}"
export RELEASE_TAG SOURCE_REVISION RENEWER_IMAGE UNIFI_IMAGE
```

The public packages can be tested without relying on cached registry
credentials:

```bash
ANONYMOUS_DOCKER_CONFIG=$(mktemp -d)
DOCKER_CONFIG="$ANONYMOUS_DOCKER_CONFIG" docker pull "$RENEWER_IMAGE"
DOCKER_CONFIG="$ANONYMOUS_DOCKER_CONFIG" docker pull "$UNIFI_IMAGE"
rm -rf -- "$ANONYMOUS_DOCKER_CONFIG"
```

Require each resolved repository digest to equal the release reference:

```bash
docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' \
  "$RENEWER_IMAGE"
docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' \
  "$UNIFI_IMAGE"
```

Inspect the OCI identity on both images. Repeat these three checks for
`$UNIFI_IMAGE`:

```bash
docker image inspect --format \
  '{{index .Config.Labels "org.opencontainers.image.source"}}' \
  "$RENEWER_IMAGE"
docker image inspect --format \
  '{{index .Config.Labels "org.opencontainers.image.version"}}' \
  "$RENEWER_IMAGE"
docker image inspect --format \
  '{{index .Config.Labels "org.opencontainers.image.revision"}}' \
  "$RENEWER_IMAGE"
```

Both images must report this repository as `source`, the chosen release tag as
`version`, and the release's exact source commit as `revision`. See
[Releasing](releasing.md) to verify GitHub provenance and SBOM attestations for
each digest.

## 3. Configure OPNsense

Use the `deployment/opnsense/ACL.xml` from the chosen release's source revision.
Transfer it to OPNsense through an existing administrator-controlled path as
`/tmp/ACL.xml`, verify the transferred public file, then run these commands in
the normal OPNsense `csh`/`tcsh` shell. They deliberately use no Bourne-shell
syntax:

```csh
install -d -o root -g wheel -m 0755 /usr/local/opnsense/mvc/app/models/LloydSmart
install -d -o root -g wheel -m 0755 /usr/local/opnsense/mvc/app/models/LloydSmart/CertificateRenewer
install -d -o root -g wheel -m 0755 /usr/local/opnsense/mvc/app/models/LloydSmart/CertificateRenewer/ACL
install -o root -g wheel -m 0644 /tmp/ACL.xml /usr/local/opnsense/mvc/app/models/LloydSmart/CertificateRenewer/ACL/ACL.xml
```

In the OPNsense web interface:

1. Confirm the new `API: Certificate Renewer` privilege is available.
2. Create or select a dedicated API-only identity for this deployment.
3. Grant that identity only `API: Certificate Renewer`.
4. Create its API key and secret, and transfer them directly to the renewer
   secret files described below.

The supplied ACL authorizes exactly:

- CA listing: `api/trust/cert/ca_list`;
- CSR signing: `api/trust/cert/add`; and
- issued public CRT retrieval: `api/trust/cert/generate_file/*/crt`.

It does not authorize private-key or PKCS#12 export, general Trust API access,
or certificate deletion. Unused certificates created by `prepare` or an
ambiguous signing attempt require a separate administrator-authorized cleanup
path. Never add deletion permission to the renewer's ACL.

## 4. Create the host runtime directory

Production currently uses numeric gid `984` for the dedicated executor group.
This gid is deployment metadata, not a secret. Confirm it is unused by unrelated
host or container processes, then create the runtime directory before either
container starts:

```bash
install -d -o root -g 984 -m 0750 /run/unifi-cert-renewer
stat -c '%u:%g %a %F %n' /run/unifi-cert-renewer
```

The expected result is numeric ownership `0:984`, mode `750`, and a directory.
Membership in gid `984` authorizes the five fixed executor operations, so do not
add unrelated processes to it.

`/run` is ephemeral on Unraid and similar hosts. Configure an existing trusted
host boot mechanism to run the `install` command on every boot, before Docker
starts either container. If the boot facility does not use a Bourne-compatible
shell, invoke `/bin/sh` explicitly. Do not let a container create the host
directory with image-default ownership.

On a systemd host, an equivalent persistent definition is:

```text
d /run/unifi-cert-renewer 0750 root 984 -
```

Place that line in an administrator-managed tmpfiles configuration, apply it
before container startup, and verify the resulting ownership and mode.

## 5. Migrate the existing UniFi deployment

This project does not provide a generic replacement Compose file for UniFi.
Start from the operator's current LinuxServer service definition and preserve
all deployment-specific settings, including:

- the existing `/config` bind or volume;
- Mongo/database configuration and credentials;
- every environment variable;
- network attachments and aliases;
- static addresses and published ports; and
- any other required LinuxServer settings.

Change or add only these project-specific items:

- set `image` to the exact released `$UNIFI_IMAGE` digest reference;
- bind `/run/unifi-cert-renewer` read-write at the same container path;
- bind the UniFi-only keystore-password file read-only at
  `/run/secrets/unifi-keystore-password`; and
- assign the stable, operator-controlled numeric network address used by
  `live_tls.address` on the network shared with the renewer.

The relevant fragment, to merge into the existing service rather than use as a
standalone definition, is:

```yaml
services:
  unifi:
    image: ${UNIFI_IMAGE:?set UNIFI_IMAGE to the released derivative digest}
    volumes:
      - type: bind
        source: /run/unifi-cert-renewer
        target: /run/unifi-cert-renewer
      - type: bind
        source: ${UNIFI_KEYSTORE_PASSWORD_FILE:?set the UniFi-only secret file}
        target: /run/secrets/unifi-keystore-password
        read_only: true
    networks:
      existing-unifi-network:
        ipv4_address: <stable-operator-controlled-address>
```

Use the operator's existing deployment tooling to inspect its resolved
configuration and recreate only the UniFi container. Do not recreate its
`/config` storage or database. Observe startup: recovery and secure-state
oneshots must succeed before the UniFi Java and executor longruns start.

## 6. Keep the secret domains separate

### UniFi-only keystore password

Provision the existing keystore password into a dedicated host area. The file
must be owned by root, mode `0600`, and mounted only into the UniFi container:

```bash
chown root:root '<host-unifi-keystore-password-file>'
chmod 0600 '<host-unifi-keystore-password-file>'
stat -c '%u:%g %a %F %n' '<host-unifi-keystore-password-file>'
```

Never mount this file or its parent directory into the renewer. Do not print,
log, commit, or copy its contents into a command line.

### Renewer secrets and public configuration

Create a different host directory for the renewer. A proven suitable permission
model is:

- directory: `root:1000`, mode `0750`;
- `renewer-config.json` and public CA files: `root:root`, mode `0444`;
- `opnsense-api-key` and `opnsense-api-secret`: `1000:1000`, mode `0400`.

For example, after securely provisioning the files without exposing their
contents:

```bash
RENEWER_SECRETS_DIRECTORY='<host-renewer-secrets-directory>'
install -d -o root -g 1000 -m 0750 "$RENEWER_SECRETS_DIRECTORY"
chown root:root \
  "$RENEWER_SECRETS_DIRECTORY/renewer-config.json" \
  "$RENEWER_SECRETS_DIRECTORY/<issuing-ca-file>" \
  "$RENEWER_SECRETS_DIRECTORY/<opnsense-https-ca-file>"
chmod 0444 \
  "$RENEWER_SECRETS_DIRECTORY/renewer-config.json" \
  "$RENEWER_SECRETS_DIRECTORY/<issuing-ca-file>" \
  "$RENEWER_SECRETS_DIRECTORY/<opnsense-https-ca-file>"
chown 1000:1000 \
  "$RENEWER_SECRETS_DIRECTORY/opnsense-api-key" \
  "$RENEWER_SECRETS_DIRECTORY/opnsense-api-secret"
chmod 0400 \
  "$RENEWER_SECRETS_DIRECTORY/opnsense-api-key" \
  "$RENEWER_SECRETS_DIRECTORY/opnsense-api-secret"
```

Omit the OPNsense HTTPS CA file commands when `opnsense.tls_ca_name` is `null`.
The issuing CA is always required. Public certificates are not secrets, but the
renewer still validates their type, ownership, mode, size, name, and contents.

The renewer receives only this directory at `/run/secrets`, the read-only
`/run/unifi-cert-renewer` bind, supplemental gid `984`, and the required shared
Docker network. It must not receive UniFi `/config`, the UniFi keystore-password
secret, or `/var/run/docker.sock`.

## 7. Configure `renewer-config.json`

Copy [the example configuration](../deployment/renewer/renewer-config.example.json)
into the renewer secrets directory and replace every example identity and
fingerprint. Keep the example fields; `renew_before_days` is optional only for
compatibility with existing `v0.1.0` configuration and defaults to 30 when
omitted.

- `certificate_policy.expected_spki_sha256`: lowercase SHA-256 of the existing
  UniFi key's DER SubjectPublicKeyInfo. Establish it from an authoritative
  public keystore certificate inspection; never export the private key.
- `certificate_policy.subject`: exact subject required on the CSR and issued
  leaf, for example the deployment's UniFi DNS identity.
- `certificate_policy.dns_sans`: complete ordered list of required DNS SANs.
- `certificate_policy.ip_sans`: complete ordered list of required IP SANs; use
  an empty list when none are required.
- `opnsense.base_url`: HTTPS origin of the intended OPNsense instance, with no
  credentials, path, query, or fragment.
- `opnsense.timeout_seconds`: positive request timeout for one OPNsense API
  request.
- `opnsense.tls_ca_name`: filename of the optional public CA used to authenticate
  OPNsense HTTPS, or `null` for the normal system trust store.
- `issuing_ca_description`: exact, unique OPNsense description of the issuing
  CA.
- `certificate_description`: operator-recognizable description assigned to each
  newly issued OPNsense certificate record.
- `trusted_ca_name`: filename of the public issuing CA used for issued-certificate
  and live UniFi TLS verification.
- `lifetime_days`: requested lifetime from 1 through 397 days.
- `renew_before_days`: independent renewal threshold from 1 through 397 days.
  The default is 30. It is intentionally independent of `lifetime_days`, and
  configuration validation does not couple the two values. If
  `renew_before_days` is greater than or equal to `lifetime_days`, a newly
  issued certificate will already be within the renewal window, so every
  scheduled check can renew it.
- `digest`: signing digest: `sha256`, `sha384`, or `sha512`.
- `live_tls.address`: stable, operator-controlled numeric IPv4 or IPv6 address
  used for the actual connection.
- `live_tls.server_hostname`: independently verified DNS name or IP identity
  expected in the certificate.
- `live_tls.port`: UniFi HTTPS port reachable from the renewer network.
- Remaining `live_tls` values: bounded overall readiness deadline, per-attempt
  timeout, retry delay, and maximum attempt count.

`live_tls.address` and `server_hostname` have different jobs. The first selects
the endpoint without an unbounded DNS lookup; the second is the identity checked
by the TLS stack. A container address assigned dynamically from a bridge network
is unsuitable because recreation can move the intended service. Reserve the
numeric address in the operator-controlled network and independently verify the
configured TLS identity.

If the existing public leaf certificate has been exported through a trusted
administrative process, its SPKI can be calculated without private-key access:

```bash
openssl x509 -in '<current-public-leaf.pem>' -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256
```

Record the leaf SHA-256, SPKI SHA-256, subject, SANs, validity, and chain as the
pre-renewal baseline. The later `inspect` and `csr` checks must reproduce the
configured identity and SPKI.

## 8. Deploy the renewer and run preflight checks

Use [the renewer Compose example](../deployment/renewer/compose.example.yaml),
which defines only the renewer service:

```bash
export RENEWER_IMAGE RENEWER_SECRETS_DIRECTORY
UNIFI_NETWORK='<existing-shared-network-name>'
export UNIFI_NETWORK
docker compose -f deployment/renewer/compose.example.yaml config
```

Inspect the complete resolved output before running a mode. It must show:

- exact `$RENEWER_IMAGE`, never a mutable tag;
- user `1000:1000` and supplemental gid `984`;
- only the runtime and renewer-secrets read-only bind mounts;
- only the required external shared network;
- read-only root filesystem, all capabilities dropped,
  `no-new-privileges`, and restart policy `no`; and
- no `/config`, keystore-password file, or Docker socket.

Verify both local image identities again and verify the configured image user:

```bash
docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' \
  "$RENEWER_IMAGE"
docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' \
  "$UNIFI_IMAGE"
docker image inspect --format '{{.Config.User}}' "$RENEWER_IMAGE"
```

The user result must be `1000:1000`. Adapt the following read-only checks to the
operator's actual UniFi container name:

```bash
UNIFI_CONTAINER='<operator-unifi-container-name>'
docker container inspect --format '{{.Config.Image}}' "$UNIFI_CONTAINER"
docker container inspect --format '{{json .Mounts}}' "$UNIFI_CONTAINER"
docker container inspect --format '{{json .NetworkSettings.Networks}}' \
  "$UNIFI_CONTAINER"
stat -c '%u:%g %a %F %n' /run/unifi-cert-renewer
stat -c '%u:%g %a %F %n' /run/unifi-cert-renewer/executor.sock
docker exec -u 0 "$UNIFI_CONTAINER" stat -c '%u:%g %a %F %n' \
  /run/unifi-cert-renewer /run/unifi-cert-renewer/executor.sock
docker exec -u 0 "$UNIFI_CONTAINER" s6-svstat \
  /run/service/svc-unifi-network-application
docker exec -u 0 "$UNIFI_CONTAINER" s6-svstat \
  /run/service/svc-unifi-cert-renewer-executor
```

Require the configured/running UniFi image reference to be the intended exact
digest. The host and container views of the directory must be `0:984`, mode
`750`; the socket must be `0:984`, mode `660`, and a socket. Both s6 longruns
must report up before renewal preflight continues.

Where cross-UID `/proc` restrictions apply, confirm the executor's fixed process
classifier succeeds:

```bash
docker exec -u 0 "$UNIFI_CONTAINER" \
  env PYTHONPATH=/opt/unifi-cert-renewer/src \
  /opt/unifi-cert-renewer/venv/bin/python -c \
  'from unifi_process import _processes; print(_processes())'
```

The normal running result is `(True, False)`: one classified UniFi JVM and no
keytool writer. See the additional same-UID inspection diagnostics in
[Production deployment](production-deployment.md#disposable-boot-evidence) if
this check fails.

Before any renewal, require all active transaction artifacts to be absent. The
persistent `.cert-renewer-lock` is expected and is not an active transaction:

```bash
docker exec -u 0 "$UNIFI_CONTAINER" find /config/data -maxdepth 1 \
  \( -name .cert-renewer-journal \
  -o -name .cert-renewer-journal-new \
  -o -name .cert-renewer-stage \
  -o -name .cert-renewer-rollback \) -print
```

Any output is a stop condition. Do not edit or delete it.

Finally run the non-mutating public baseline:

```bash
docker compose -f deployment/renewer/compose.example.yaml run --rm renewer inspect
```

Record the returned certificate SHA-256 and SPKI SHA-256. Confirm the SPKI,
subject, SANs, and other public identity match the approved configuration and
pre-migration baseline.

Before any `prepare` or `install` operation, also establish a live TLS baseline
from the renewer's operator-controlled Docker network. This diagnostic overrides
the released image's entrypoint only for one read-only Python invocation; it uses
the mounted production configuration and issuing CA, but does not contact the
executor or OPNsense and does not create or alter transaction state:

```bash
docker compose -f deployment/renewer/compose.example.yaml run --rm --no-TTY \
  --entrypoint python renewer - <<'PY'
import json
import socket
from ipaddress import ip_address

from certificate import inspect_certificate
from production_renewer import _read_trusted_ca, load_production_config
from tls_policy import create_client_tls_context

config = load_production_config()
endpoint = config.live_endpoint
readiness = config.readiness
if endpoint is None or readiness is None:
    raise RuntimeError("live_tls must be configured")
context = create_client_tls_context(
    ca_data=_read_trusted_ca(config.trusted_ca_name)
)
family = socket.AF_INET6 if ip_address(endpoint.address).version == 6 \
    else socket.AF_INET
with socket.socket(family, socket.SOCK_STREAM) as raw:
    raw.settimeout(float(readiness.attempt_timeout_seconds))
    raw.connect((endpoint.address, endpoint.port))
    with context.wrap_socket(
        raw, server_hostname=endpoint.server_hostname
    ) as connection:
        leaf = connection.getpeercert(binary_form=True)
inspection = inspect_certificate(leaf)
print(json.dumps({
    "certificate_sha256": inspection.certificate_sha256,
    "spki_sha256": inspection.spki_sha256,
}, sort_keys=True))
PY
```

The connection goes to the configured numeric `live_tls.address` and port while
the TLS stack verifies `server_hostname` and the chain against `trusted_ca_name`.
Require both reported hashes to equal the authoritative `inspect` baseline.
Stop on an unreachable or incorrect address, wrong server hostname, trust
failure, or unexpected live leaf. This check exists to catch each of those
conditions before UniFi is mutated; it does not sign or generate a certificate,
install anything, restart UniFi, or touch transaction state.

## 9. Perform the first supervised operation

Run each command manually and review its public JSON before continuing:

```bash
docker compose -f deployment/renewer/compose.example.yaml run --rm renewer inspect
docker compose -f deployment/renewer/compose.example.yaml run --rm renewer csr
```

`inspect` only reads and validates public certificate/keystore metadata. `csr`
asks the executor to create a public CSR with the existing key and validates its
identity, SPKI, and proof-of-possession. Neither signs a certificate nor modifies
the installed certificate.

An acceptance run may optionally exercise preparation:

```bash
docker compose -f deployment/renewer/compose.example.yaml run --rm renewer prepare
```

`prepare` is not a dry run. It creates a certificate record in OPNsense and
validates the public result, but does not modify UniFi. The stateless renewer does
not retain that candidate. A later `install` signs a fresh certificate instead
of reusing the prepared one. Remove unused preparation certificates later
through the separate OPNsense administrator path; do not grant delete access to
the renewer.

When every prior result is approved, invoke installation exactly once under
supervision:

```bash
docker compose -f deployment/renewer/compose.example.yaml run --rm renewer install
```

`install` is the explicit force-renew-now mode. It performs a fresh inspect,
CSR, sign, validation, guarded installation, UniFi restart, verified live TLS
connection, exact issued-leaf comparison, and executor finalisation regardless
of the current certificate's remaining validity. Success requires JSON with
`state` equal to `renewal_complete` and `renewal_complete` equal to `true`.

After an ambiguous or failed signing, installation, live verification, or
finalisation operation, do not invoke `install`, `prepare`, or another signing
path again. Follow the failure rules below.

## 10. Independently verify the completed installation

Retain the successful `install` JSON as public transaction evidence. Independently
connect to the configured stable address with normal CA and hostname
verification. In a Bash shell, for a DNS `server_hostname`:

```bash
set -o pipefail
UNIFI_ADDRESS='<stable-numeric-address>'
UNIFI_PORT='<configured-https-port>'
UNIFI_SERVER_NAME='<configured-dns-server-hostname>'
ISSUING_CA='<host-path-to-public-issuing-ca>'
case "$UNIFI_ADDRESS" in
  *:*) UNIFI_CONNECT="[${UNIFI_ADDRESS}]:${UNIFI_PORT}" ;;
  *) UNIFI_CONNECT="${UNIFI_ADDRESS}:${UNIFI_PORT}" ;;
esac
readonly UNIFI_CONNECT
openssl s_client \
  -connect "$UNIFI_CONNECT" \
  -servername "$UNIFI_SERVER_NAME" \
  -verify_hostname "$UNIFI_SERVER_NAME" \
  -verify_return_error \
  -CAfile "$ISSUING_CA" </dev/null \
  | openssl x509 -outform DER \
  | openssl dgst -sha256
```

Enter a numeric IPv6 `UNIFI_ADDRESS` without brackets, exactly as it appears in
the JSON configuration. The shell construction adds brackets only to the
OpenSSL `host:port` connection target.

For an IP `server_hostname`, use `-verify_ip "$UNIFI_SERVER_NAME"` instead of
`-verify_hostname`. Do not use an unverified TLS option. The resulting leaf
SHA-256 must exactly equal `issued_certificate.certificate_sha256` from the one
successful `install` output.

Verify SPKI continuity over another fully verified connection:

```bash
openssl s_client \
  -connect "$UNIFI_CONNECT" \
  -servername "$UNIFI_SERVER_NAME" \
  -verify_hostname "$UNIFI_SERVER_NAME" \
  -verify_return_error \
  -CAfile "$ISSUING_CA" </dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256
```

Again substitute `-verify_ip` for an IP identity. The SPKI must equal both the
configured expected SPKI and the pre-renewal baseline.

Run a fresh public keystore inspection and compare its certificate SHA-256 and
SPKI to the issued/live values:

```bash
docker compose -f deployment/renewer/compose.example.yaml run --rm renewer inspect
```

Check the protected canonical file's metadata without reading its contents:

```bash
docker exec -u 0 "$UNIFI_CONTAINER" stat -c '%u:%g %a %F %n' \
  /config/data/keystore
```

It must remain a regular file owned by `1000:1000`, mode `600`. Repeat the
transaction-artifact `find` check from preflight and require no output after
successful finalisation. Repeat the socket and process-classification checks;
the socket must still be `0:984`, mode `660`, and the expected process result is
`(True, False)`. Independently require both longruns to remain up:

```bash
docker exec -u 0 "$UNIFI_CONTAINER" s6-svstat \
  /run/service/svc-unifi-network-application
docker exec -u 0 "$UNIFI_CONTAINER" s6-svstat \
  /run/service/svc-unifi-cert-renewer-executor
```

Finally confirm the running UniFi container and every subsequent renewer
one-shot still reference the selected exact release digests:

```bash
docker container inspect --format '{{.Config.Image}}' "$UNIFI_CONTAINER"
docker compose -f deployment/renewer/compose.example.yaml config --images
```

Clean up only unused OPNsense certificate records through the separate
administrator path. Retain the record for the successfully installed
certificate.

### Schedule routine threshold checks

After the supervised installation and independent verification succeed, the
`renew` mode is the application entrypoint intended for a separately managed
cron job or Unraid User Scripts schedule:

```bash
flock --nonblock /run/lock/unifi-cert-renewer-renew.lock \
  docker compose -f deployment/renewer/compose.example.yaml run --rm renewer renew
```

Continue to set both production image references to the reviewed immutable
release digests; a scheduler must not substitute mutable tags. Every external
scheduled invocation must use the same operator-controlled host lock, through
`flock` or equivalent overlap protection, so concurrent scheduler runs cannot
both proceed through the due path. A daily invocation is safe when the
certificate is outside the configured window:
`renew` validates the current public certificate, returns exit status zero with
`state=renewal_not_due`, and performs no CA read, CSR generation, OPNsense API
access, signing, installation, restart, or transaction-state creation. At the
exact threshold or inside it, `renew` uses the same guarded installation and
live-verification path as `install`.

This repository does not create or deploy that schedule. Configure the external
scheduler to retain the machine-readable output and alert on a nonzero exit.
After any ambiguous state-changing failure, disable further scheduled
invocations and apply the failure rules below; do not turn `renew` into a retry
loop.

## 11. Upgrade to another release

Upgrade only while there is no active transaction. For both new images:

1. Obtain the new tag, source revision, and exact digests from its GitHub
   release.
2. Pull the exact digest references, anonymously where appropriate.
3. Verify each repository digest and the OCI `source`, `version`, and `revision`
   labels as in release selection. Verify attestations where required.
4. Change only the relevant image digest in the operator's existing deployment.
   Do not replace preserved UniFi settings with the example fragment.
5. Inspect the resolved deployment diff and confirm no mount, identity, network,
   address, secret, or security setting changed unexpectedly.
6. Recreate only the intended container. Verify it completely before changing
   the other image reference.

When recreating the UniFi derivative, observe startup recovery, confirm Java and
the executor become eligible in order, and recheck the runtime directory,
socket, stable network address, process classification, keystore metadata, and
verified live TLS. When changing the renewer image, recheck user `1000:1000`,
supplemental gid `984`, mounts, network, dropped capabilities, and restart
policy.

Check each upgraded longrun separately:

```bash
docker exec -u 0 "$UNIFI_CONTAINER" s6-svstat \
  /run/service/svc-unifi-network-application
docker exec -u 0 "$UNIFI_CONTAINER" s6-svstat \
  /run/service/svc-unifi-cert-renewer-executor
```

After both intended digest changes are verified, run only the non-mutating
renewer check:

```bash
docker compose -f deployment/renewer/compose.example.yaml run --rm renewer inspect
```

Review the result before authorizing a later supervised renewal. Rebuilding the
repository locally does not produce or prove the released registry artifact and
is not an alternative to deploying the release digest.

## 12. Failure and recovery rules

> **Stop after any ambiguous or failed signing, installation, verification,
> finalisation, recovery, or startup result. Do not retry automatically.**

Preserve `.cert-renewer-*` transaction evidence and current public file metadata.
In particular:

- do not edit, move, or delete transaction files;
- do not force UniFi Java back up around failed recovery;
- do not automatically re-sign or run `prepare` again;
- do not automatically re-import or run `install` again;
- do not broaden the executor operation set, socket access, container
  privileges, or OPNsense ACL to recover; and
- do not treat a successful filesystem recovery as proof of a successful
  renewal.

Keep the protected appdata recovery reference available. Capture the bounded
operator diagnostic, container state, public file metadata, and executor/s6
state without exposing secrets. Then consult
[Executor and recovery](unifi-executor.md#startup-and-explicit-recovery) and make
an explicit recovery decision from the recorded durable state.
