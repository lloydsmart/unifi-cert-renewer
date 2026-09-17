#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 2 || -z $1 || $1 == -* || -z $2 || $2 == -* ]]; then
    printf 'Usage: %s RENEWER_IMAGE UNIFI_IMAGE\n' "$0" >&2
    exit 2
fi

renewer_image=$1
unifi_image=$2

if ! command -v docker >/dev/null 2>&1; then
    printf '%s\n' 'Docker is required but is not available on PATH.' >&2
    exit 1
fi

for image in "$renewer_image" "$unifi_image"; do
    if ! docker image inspect "$image" >/dev/null 2>&1; then
        printf 'Container image does not exist locally: %q\n' "$image" >&2
        exit 1
    fi
done

if [[ $(docker image inspect --format '{{.Config.User}}' "$renewer_image") != \
    '1000:1000' ]]; then
    printf '%s\n' 'Renewer image configured user is not 1000:1000.' >&2
    exit 1
fi

docker run --rm \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --entrypoint /bin/sh \
    "$renewer_image" \
    -ceu '
        test "$(id -u):$(id -g)" = "1000:1000"
        test -f /opt/unifi-cert-renewer/src/unifi_executor_client.py
        test -f /opt/unifi-cert-renewer/src/unifi_executor_service.py
        test ! -e /opt/unifi-cert-renewer/src/unifi_executor.py
        test ! -e /opt/unifi-cert-renewer/src/unifi_executor_files.py
        test ! -e /opt/unifi-cert-renewer/src/unifi_process.py
    '

# Import the real entrypoint under the production restrictions. Its help/usage
# path deliberately returns 2 before reading configuration or using the socket.
usage_status=0
usage_output=$(
    docker run --rm \
        --network none \
        --read-only \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
        --cap-drop ALL \
        --security-opt no-new-privileges:true \
        "$renewer_image" --help 2>&1
) || usage_status=$?
if [[ "$usage_status" -ne 2 || "$usage_output" != \
    'Usage: production_renewer.py {inspect|csr|prepare|install|renew}' ]]; then
    printf '%s\n' 'Renewer entrypoint did not return its expected usage response.' >&2
    exit 1
fi

docker run --rm \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --entrypoint python \
    "$renewer_image" \
    -c 'import importlib.metadata as metadata; import importlib.util as util
for name in ("pip", "ensurepip", "setuptools", "pkg_resources", "msgpack"):
    assert util.find_spec(name) is None, f"Unexpected build-time tooling: {name}"
assert not any(
    (dist.metadata.get("Name") or "").lower() in {"pip", "setuptools", "msgpack"}
    for dist in metadata.distributions()
)
'

docker run --rm \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --entrypoint /bin/sh \
    "$unifi_image" \
    -ceu '
        test ! -e /usr/bin/pebble
        test -f /opt/unifi-cert-renewer/src/unifi_executor.py
        test -f /opt/unifi-cert-renewer/src/unifi_executor_files.py
        test -f /opt/unifi-cert-renewer/src/unifi_process.py
        test -x /etc/s6-overlay/s6-rc.d/init-unifi-cert-renewer-recovery/run
        test -x /etc/s6-overlay/s6-rc.d/init-unifi-cert-renewer-secure-state/run
        test -x /etc/s6-overlay/s6-rc.d/svc-unifi-cert-renewer-executor/run
    '

printf '%s\n' 'Validated renewer and UniFi image packaging boundaries'
