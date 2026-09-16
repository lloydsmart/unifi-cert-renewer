# Releasing

The release workflow publishes the two production container images only when a
protected tag matching `v*` is pushed. Ordinary branch pushes, pull requests,
and manual workflow runs cannot publish.

Release candidate `v0.1.0-rc.2` was published on 2026-09-15 and subsequently
exercised in production using its exact released image digests. Operators
consuming a release should follow the
[installation and operation runbook](installation.md); this document describes
publisher provenance, digest, and attestation controls.

## Prerequisites

- The release commit is merged to and reachable from `main`.
- Required CI and repository rules have passed for that commit.
- The operator has the release signing key with fingerprint
  `02EBB31CC0032A86C2C0401A1534542E61DC82D3`.
- The active `Protect release tags` ruleset prevents updates and deletion of
  `v*` tags.
- GitHub Actions can create packages, attestations, and releases with its
  short-lived `GITHUB_TOKEN`. No PAT or registry secret is used.

Confirm the local key fingerprint before tagging:

```bash
gpg --list-secret-keys --with-subkey-fingerprint \
  02EBB31CC0032A86C2C0401A1534542E61DC82D3
```

The initial release policy accepts only:

- `vMAJOR.MINOR.PATCH`
- `vMAJOR.MINOR.PATCH-rc.N`, where `N` is a positive integer

Numeric components do not use leading zeroes, except for the number zero
itself. Other prerelease or build-metadata forms are rejected even though the
trigger pattern is broader.

## Create the signed tag

Start from the current protected branch and create an annotated signed tag. Do
not move or replace a release tag after pushing it.

```bash
git checkout main
git pull --ff-only
RELEASE_TAG='<new-release-tag>'
git tag -s "$RELEASE_TAG" -m "$RELEASE_TAG"
git tag -v "$RELEASE_TAG"
git push origin "$RELEASE_TAG"
```

Before any build or publication, the workflow queries GitHub's REST API for the
tag ref and annotated tag object. It requires an annotated tag that points
directly to a commit, an exact tag-name match, and GitHub verification fields
`verified: true` and `reason: valid`. The checked-out commit must equal the tag
target and be an ancestor of `origin/main`. Lightweight, malformed, unsigned,
unverified, indirectly targeted, or off-main tags fail closed.

## Published artifacts

The version tag is published to:

- `ghcr.io/lloydsmart/unifi-cert-renewer:<version>`
- `ghcr.io/lloydsmart/unifi-network-application-cert-renewer:<version>`

The initial pipeline does not publish `latest`. It builds each image once,
records the local image ID, validates and scans that exact ID, creates an SPDX
JSON SBOM from a saved archive of that ID, and tags that same ID for GHCR. After
the push, it pulls the registry digest and requires its Docker config identity
to equal the tested local image ID.

Rerunning a partially successful release is safe only when every existing
version tag resolves to the exact same Docker image/config ID as the image the
retry independently built, checked, and scanned. In that case the workflow
reuses the existing immutable digest without pushing the tag again. Different
existing content is never overwritten and causes the retry to fail closed.

The GitHub Release records the exact source commit and both immutable image
digests. It also contains both SPDX JSON SBOM files. Production deployment must
use the digest reference shown in the release, for example:

```bash
docker pull \
  ghcr.io/lloydsmart/unifi-cert-renewer@sha256:<release-digest>
```

Confirm the downloaded reference and image metadata:

```bash
docker image inspect --format '{{json .RepoDigests}}' \
  ghcr.io/lloydsmart/unifi-cert-renewer@sha256:<release-digest>
docker image inspect --format '{{json .Config.Labels}}' \
  ghcr.io/lloydsmart/unifi-cert-renewer@sha256:<release-digest>
```

The labels identify this repository, the exact source revision, and the
release version.

## Verify attestations

GitHub-native provenance and SBOM attestations are attached to each published
digest and pushed to GHCR. Verify provenance with GitHub CLI:

```bash
gh attestation verify \
  oci://ghcr.io/lloydsmart/unifi-cert-renewer@sha256:<release-digest> \
  --repo lloydsmart/unifi-cert-renewer \
  --signer-workflow \
  lloydsmart/unifi-cert-renewer/.github/workflows/release.yml
```

Verify the SPDX 2.3 SBOM attestation by adding its predicate type:

```bash
gh attestation verify \
  oci://ghcr.io/lloydsmart/unifi-cert-renewer@sha256:<release-digest> \
  --repo lloydsmart/unifi-cert-renewer \
  --signer-workflow \
  lloydsmart/unifi-cert-renewer/.github/workflows/release.yml \
  --predicate-type https://spdx.dev/Document/v2.3
```

Repeat both commands for the UniFi derivative digest.

## One-time GHCR visibility step

GitHub currently creates a newly published container package as private even
when its source repository is public. `GITHUB_TOKEN` publication and the
`org.opencontainers.image.source` label link each package to this repository,
but they do not guarantee public visibility. A long-lived PAT is deliberately
not used to change this setting.

When a newly published package is still private, open each package in GitHub, choose
**Package settings**, then **Change visibility**, and set it to **Public**:

- `unifi-cert-renewer`
- `unifi-network-application-cert-renewer`

Release-candidate acceptance requires unauthenticated pulls of both exact
digests. Use a new empty Docker configuration so existing credentials cannot
make the check pass accidentally:

```bash
unauthenticated_config=$(mktemp -d)
DOCKER_CONFIG="$unauthenticated_config" docker pull \
  ghcr.io/lloydsmart/unifi-cert-renewer@sha256:<release-digest>
DOCKER_CONFIG="$unauthenticated_config" docker pull \
  ghcr.io/lloydsmart/unifi-network-application-cert-renewer@sha256:<release-digest>
rm -rf -- "$unauthenticated_config"
```

Do not declare a release candidate accepted until both pulls succeed.

## Stable-release sequence

1. Require the selected release candidate's workflow, both image publications,
   all attestations, and GitHub prerelease to have succeeded.
2. Confirm both packages are public and their exact digests pull without
   authentication.
3. Deploy the exact release-candidate digests to production and complete the
   supervised smoke and renewal verification.
4. After approval, create and locally verify a signed annotated stable tag on
   the approved `main` commit, then push it.
5. Verify the stable workflow result and deploy only its recorded immutable
   digests.

An `-rc.N` tag creates a GitHub prerelease. A stable version tag creates a
normal GitHub Release. The release is created only after both images have
passed package checks and vulnerability comparison, SBOM generation,
publication identity verification, and provenance and SBOM attestation.
