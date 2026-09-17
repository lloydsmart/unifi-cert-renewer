# Releasing

The release workflow publishes the two production container images only when a
protected tag matching `v*` is pushed. Ordinary branch pushes, pull requests,
and manual workflow runs cannot publish.

Release candidate `v0.1.0-rc.2` was published on 2026-09-15 and subsequently
exercised in production using its exact released image digests. Stable `v0.1.0`
has since been published and production-verified using its exact released
images. Operators consuming a release should follow the
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

## Separate verification and publication

The `verify` job builds, checks, scans, and generates SBOMs with only
`contents: read`. It has no package-write, attestation-write, or OIDC permission.
Both tested image archives and both SBOMs cross to a fresh `publish` runner in
one immutable, same-run artifact selected by its numeric artifact ID. Artifact
digest mismatch is an error. The candidate manifest binds the fixed file set,
SHA-256 hashes, tested image IDs, repository, source commit, release tag, run ID,
and run attempt. Missing, extra, linked, malformed, oversized, or mismatched
inputs stop publication before loading the images or authenticating to GHCR.

The publisher checks out its reviewed control scripts from the workflow event's
immutable source SHA, with checkout credentials persistence disabled. It
independently repeats the signed-tag and main-ancestry checks. It installs no
dependencies and does not build, test, scan, or start candidate containers.
After loading the archives, it checks both image IDs and release labels again
before registry login. It then uses the existing no-overwrite publisher and
creates all four attestations. A separate finalizer alone has `contents: write`
and creates the GitHub Release after publication succeeds. It downloads the
publisher's SBOM artifact by its exact ID with strict digest checking, so an
artifact with a reused name cannot replace the release assets.

The manifest is an integrity and identity check, not proof that a compromised
build runner produced safe software or honestly ran its checks. The reviewed
workflow and publisher controls, GitHub artifact service, Actions, and Docker
archive parser remain trusted. No executable code is taken from the candidate
artifact. Complete qualification of every exact release commit, an enforced
release-signer allowlist, and the broader immutable-release protocol remain
follow-up work; this job split does not implement those controls.

Candidate artifacts expire after one day. Rerunning only failed jobs in another
run attempt fails the candidate identity check: rerun the entire workflow to
rebuild and revalidate. A rebuilt candidate must still satisfy the existing
version-tag identity rule below. Any workflow rerun or publication requires the
operator's authorization.

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
