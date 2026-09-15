#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 3 || -z $1 || -z $2 || -z $3 ]]; then
    printf 'Usage: %s TESTED_IMAGE_ID REPOSITORY RELEASE_TAG\n' "$0" >&2
    exit 2
fi

tested_image_id=$1
repository=$2
release_tag=$3
release_ref="$repository:$release_tag"

if [[ ! $tested_image_id =~ ^sha256:[0-9a-f]{64}$ ]]; then
    printf '%s\n' 'Tested image ID must be sha256 followed by 64 lowercase hex characters.' >&2
    exit 2
fi
if [[ ! $repository =~ ^ghcr\.io/[a-z0-9]+([._-][a-z0-9]+)*/[a-z0-9]+([._-][a-z0-9]+)*$ ]]; then
    printf '%s\n' 'Release repository is not a supported GHCR repository name.' >&2
    exit 2
fi
if [[ $release_tag == -* || $release_tag == *:* || $release_tag == *@* ]]; then
    printf '%s\n' 'Release tag is not safe for a container reference.' >&2
    exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
    printf '%s\n' 'Docker is required but is not available on PATH.' >&2
    exit 1
fi
if [[ $(docker image inspect --format '{{.Id}}' "$tested_image_id") != \
    "$tested_image_id" ]]; then
    printf '%s\n' 'Tested local image ID cannot be resolved exactly.' >&2
    exit 1
fi

temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/unifi-release-publish.XXXXXX")
cleanup() {
    rm -rf -- "$temporary_directory"
}
trap cleanup EXIT

manifest_diagnostic="$temporary_directory/manifest-diagnostic"
push_output="$temporary_directory/push-output"

manifest_is_absent() {
    local diagnostic=$1
    local -a nonempty_lines=()
    mapfile -t nonempty_lines < <(sed '/^[[:space:]]*$/d' "$diagnostic")
    [[ ${#nonempty_lines[@]} -eq 1 ]] && \
        [[ ${nonempty_lines[0]} =~ ^[[:space:]]*(manifest[[:space:]]unknown|no[[:space:]]such[[:space:]]manifest(:[^[:cntrl:]]*)?)[[:space:]]*$ ]]
}

resolve_existing_digest() {
    local reference=$1
    local expected_repository=$2
    local candidate
    local -a matching_digests=()

    while IFS= read -r candidate; do
        if [[ $candidate == "$expected_repository"@sha256:* ]]; then
            matching_digests+=("${candidate#*@}")
        fi
    done < <(
        docker image inspect \
            --format '{{range .RepoDigests}}{{println .}}{{end}}' \
            "$reference"
    )

    if [[ ${#matching_digests[@]} -ne 1 ]] || \
        [[ ! ${matching_digests[0]} =~ ^sha256:[0-9a-f]{64}$ ]]; then
        printf 'Could not resolve one strict registry digest for %s.\n' \
            "$reference" >&2
        return 1
    fi
    printf '%s' "${matching_digests[0]}"
}

if docker manifest inspect "$release_ref" >/dev/null 2>"$manifest_diagnostic"; then
    printf 'Release image tag already exists; verifying exact identity: %s\n' \
        "$release_ref" >&2
    docker pull "$release_ref" >&2
    digest=$(resolve_existing_digest "$release_ref" "$repository")
    existing_image_id=$(docker image inspect --format '{{.Id}}' "$release_ref")
    if [[ $existing_image_id != "$tested_image_id" ]]; then
        printf 'Existing release tag refers to different content and will not be overwritten: %s\n' \
            "$release_ref" >&2
        printf 'Tested image ID: %s\nExisting image ID: %s\n' \
            "$tested_image_id" "$existing_image_id" >&2
        exit 1
    fi
else
    if ! manifest_is_absent "$manifest_diagnostic"; then
        cat "$manifest_diagnostic" >&2
        printf 'Could not determine whether release image tag exists: %s\n' \
            "$release_ref" >&2
        exit 1
    fi

    printf 'Release image tag is unused; publishing tested image: %s\n' \
        "$release_ref" >&2
    docker tag "$tested_image_id" "$release_ref"
    if [[ $(docker image inspect --format '{{.Id}}' "$release_ref") != \
        "$tested_image_id" ]]; then
        printf '%s\n' 'Local release tag does not identify the tested image.' >&2
        exit 1
    fi
    docker push "$release_ref" | tee "$push_output" >&2
    mapfile -t pushed_digests < <(
        sed -nE \
            's/^.*digest: (sha256:[0-9a-f]{64}) size:.*$/\1/p' \
            "$push_output"
    )
    if [[ ${#pushed_digests[@]} -ne 1 ]]; then
        printf 'Could not capture one registry digest for %s.\n' \
            "$release_ref" >&2
        exit 1
    fi
    digest=${pushed_digests[0]}
fi

if [[ ! $digest =~ ^sha256:[0-9a-f]{64}$ ]]; then
    printf 'Registry returned an invalid digest for %s.\n' "$release_ref" >&2
    exit 1
fi

docker pull "$repository@$digest" >&2
published_image_id=$(
    docker image inspect --format '{{.Id}}' "$repository@$digest"
)
if [[ $published_image_id != "$tested_image_id" ]]; then
    printf 'Published image identity differs from tested image: %s@%s\n' \
        "$repository" "$digest" >&2
    exit 1
fi

printf '%s' "$digest"
