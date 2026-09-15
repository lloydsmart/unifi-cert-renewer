#!/usr/bin/env bash

set -euo pipefail

readonly trivy_image='ghcr.io/aquasecurity/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969'
readonly comparator_image='python:3.14-slim-bookworm@sha256:9ab8d9c8514b44f90cf0029dd42fdd7e9e211e639c8b995304cc04568dee900f'

if [[ $# -ne 2 || -z $1 || $1 == -* || -z $2 || $2 == -* ]]; then
    printf 'Usage: %s DERIVATIVE_IMAGE EXACT_UPSTREAM_IMAGE\n' "$0" >&2
    exit 2
fi

derivative_image=$1
upstream_image=$2

if ! command -v docker >/dev/null 2>&1; then
    printf '%s\n' 'Docker is required but is not available on PATH.' >&2
    exit 1
fi

for image in "$derivative_image" "$upstream_image"; do
    if ! docker image inspect "$image" >/dev/null 2>&1; then
        printf 'Container image does not exist locally: %q\n' "$image" >&2
        exit 1
    fi
done

temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/unifi-cert-renewer-trivy.XXXXXX")
cleanup() {
    rm -rf -- "$temporary_directory"
}
trap cleanup EXIT

derivative_archive="$temporary_directory/derivative-image.tar"
upstream_archive="$temporary_directory/upstream-image.tar"
cache_directory="$temporary_directory/cache"
trivy_tmp_directory="$temporary_directory/tmp"
output_directory="$temporary_directory/output"
mkdir -- "$cache_directory" "$trivy_tmp_directory" "$output_directory"

docker save --output "$derivative_archive" "$derivative_image"
docker save --output "$upstream_archive" "$upstream_image"

run_trivy_database_download() {
    local database_flag=$1

    docker run --rm \
        --read-only \
        --cap-drop ALL \
        --security-opt no-new-privileges:true \
        --user "$(id -u):$(id -g)" \
        --env HOME=/tmp \
        --env TMPDIR=/trivy-tmp \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
        --mount "type=bind,src=$cache_directory,dst=/cache" \
        --mount "type=bind,src=$trivy_tmp_directory,dst=/trivy-tmp" \
        "$trivy_image" \
        --cache-dir /cache \
        image \
        "$database_flag" \
        --no-progress
}

run_trivy_scan() {
    local archive=$1
    local output_name=$2

    docker run --rm \
        --read-only \
        --cap-drop ALL \
        --security-opt no-new-privileges:true \
        --user "$(id -u):$(id -g)" \
        --env HOME=/tmp \
        --env TMPDIR=/trivy-tmp \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
        --mount "type=bind,src=$archive,dst=/scan/image.tar,readonly" \
        --mount "type=bind,src=$cache_directory,dst=/cache" \
        --mount "type=bind,src=$trivy_tmp_directory,dst=/trivy-tmp" \
        --mount "type=bind,src=$output_directory,dst=/output" \
        "$trivy_image" \
        --cache-dir /cache \
        image \
        --input /scan/image.tar \
        --scanners vuln \
        --severity HIGH,CRITICAL \
        --list-all-pkgs=false \
        --format json \
        --output "/output/$output_name" \
        --exit-code 0 \
        --skip-db-update \
        --skip-java-db-update \
        --skip-version-check
}

printf '%s\n' 'Downloading shared vulnerability database snapshots for both scans'
run_trivy_database_download --download-db-only
run_trivy_database_download --download-java-db-only

printf '%s\n' 'Scanning derivative image for HIGH/CRITICAL vulnerabilities'
run_trivy_scan "$derivative_archive" derivative.json

printf '%s\n' 'Scanning exact upstream image for HIGH/CRITICAL vulnerabilities'
run_trivy_scan "$upstream_archive" upstream.json

script_directory=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
docker run --rm \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --user "$(id -u):$(id -g)" \
    --env HOME=/tmp \
    --env PYTHONDONTWRITEBYTECODE=1 \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
    --mount "type=bind,src=$script_directory/compare_container_vulnerabilities.py,dst=/compare.py,readonly" \
    --mount "type=bind,src=$output_directory/derivative.json,dst=/derivative.json,readonly" \
    --mount "type=bind,src=$output_directory/upstream.json,dst=/upstream.json,readonly" \
    "$comparator_image" \
    python /compare.py /derivative.json /upstream.json
