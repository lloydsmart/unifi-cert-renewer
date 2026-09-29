#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 || -z $1 || $1 == -* ]]; then
    printf 'Usage: %s RENEWER_IMAGE\n' "$0" >&2
    exit 2
fi

renewer_image=$1
test_root=$(mktemp -d /tmp/unifi-cert-renewer-f07.XXXXXXXX)
lock_directory=$test_root/lifecycle
holder_name=unifi-cert-renewer-f07-holder-$$-$RANDOM
contender_name=unifi-cert-renewer-f07-contender-$$-$RANDOM
probe_name=unifi-cert-renewer-f07-probe-$$-$RANDOM

cleanup() {
    status=$?
    trap - EXIT INT TERM
    for container in "$holder_name" "$contender_name" "$probe_name"; do
        docker rm -f "$container" >/dev/null 2>&1 || true
    done
    if ! sudo rm -rf -- "$test_root"; then
        printf 'Could not remove F07 test directory: %s\n' "$test_root" >&2
        status=1
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

docker image inspect "$renewer_image" >/dev/null

# Provision once on the host. The worker may open and flock this inode only.
sudo install -d -o root -g 1000 -m 0750 "$lock_directory"
sudo install -o root -g 1000 -m 0660 /dev/null "$lock_directory/renewal.lock"
if [[ $(sudo stat -c '%u:%g:%a' "$lock_directory") != '0:1000:750' ]] ||
    [[ $(sudo stat -c '%u:%g:%a:%h:%s' "$lock_directory/renewal.lock") != '0:1000:660:1:0' ]] ||
    ! sudo test -f "$lock_directory/renewal.lock"; then
    printf '%s\n' 'Host lifecycle lock provisioning differs from production.' >&2
    exit 1
fi
lock_inode=$(sudo stat -c '%d:%i' "$lock_directory/renewal.lock")

holder_code=$'import time\nfrom production_renewer import _lifecycle_lock\nwith _lifecycle_lock():\n    print("F07_LOCK_HELD", flush=True)\n    time.sleep(300)\n'
docker run -d \
    --name "$holder_name" \
    --user 1000:1000 \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --mount "type=bind,source=$lock_directory,target=/run/unifi-cert-renewer-lifecycle" \
    --entrypoint python \
    "$renewer_image" -u -c "$holder_code" >/dev/null

held=false
for ((attempt = 0; attempt < 100; attempt++)); do
    if docker logs "$holder_name" 2>&1 | grep -Fxq 'F07_LOCK_HELD'; then
        held=true
        break
    fi
    if [[ $(docker inspect --format '{{.State.Running}}' "$holder_name") != 'true' ]]; then
        docker logs "$holder_name" >&2
        printf '%s\n' 'Lifecycle lock holder exited before signalling readiness.' >&2
        exit 1
    fi
    sleep 0.2
done
if [[ $held != true ]]; then
    docker logs "$holder_name" >&2
    printf '%s\n' 'Lifecycle lock holder did not signal readiness.' >&2
    exit 1
fi

busy_stdout=$test_root/busy.stdout
busy_stderr=$test_root/busy.stderr
busy_status=0
timeout --kill-after=5s 30s docker run --rm \
    --name "$contender_name" \
    --user 1000:1000 \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --mount "type=bind,source=$lock_directory,target=/run/unifi-cert-renewer-lifecycle" \
    "$renewer_image" renew >"$busy_stdout" 2>"$busy_stderr" || busy_status=$?
if [[ $busy_status -ne 75 ]]; then
    cat "$busy_stderr" >&2
    printf 'Contending renewer exited %s instead of 75.\n' "$busy_status" >&2
    exit 1
fi
python3 - "$busy_stdout" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    result = json.load(stream)
expected = {"mode": "renew", "state": "busy", "renewal_complete": False}
if result != expected:
    raise SystemExit("Contending renewer did not emit the exact busy result")
PY

docker stop --time 2 "$holder_name" >/dev/null
docker wait "$holder_name" >/dev/null
docker rm "$holder_name" >/dev/null

probe_code=$'from production_renewer import _lifecycle_lock\nwith _lifecycle_lock():\n    print("F07_LOCK_REACQUIRED", flush=True)\n'
probe_output=$(timeout --kill-after=5s 30s docker run --rm \
    --name "$probe_name" \
    --user 1000:1000 \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --mount "type=bind,source=$lock_directory,target=/run/unifi-cert-renewer-lifecycle" \
    --entrypoint python \
    "$renewer_image" -u -c "$probe_code")
if [[ $probe_output != 'F07_LOCK_REACQUIRED' ]] ||
    [[ $(sudo stat -c '%d:%i' "$lock_directory/renewal.lock") != "$lock_inode" ]]; then
    printf '%s\n' 'Lifecycle lock was not reacquired on the same host inode.' >&2
    exit 1
fi

printf '%s\n' 'Validated two-container lifecycle contention and lock release'
