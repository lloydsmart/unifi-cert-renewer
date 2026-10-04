# Local worker image qualification — 2026-10-04

## Decision and identities

Qualify Trixie for the renewal worker on **linux/amd64, with the local validation
caveats below**. This working-tree proposal does not establish production
qualification. Main was fetched and verified as
`cfce0d86a6329b37507391a1dcc1500a88c96853`. Qualification used an isolated
worktree at `/tmp/unifi-cert-renewer-trixie-20261004`, on
`maintenance/qualify-trixie-worker-20261004`. PR #77 and its clean original
checkout at `8b11296461e420560ed186cc6790f8cde80d3d4f` remained untouched.

Old exact upstream, Python 3.14.7 / Debian 12.15:

```text
python:3.14-slim-bookworm@sha256:82bc3c539b8813ada9d68c63b40158fa002f7f33de9bf3312a3dfdc0620dff56
```

Selected current upstream (option B), Python 3.14.8 / Debian 13.7 (Trixie):

```text
python:3.14-slim-trixie@sha256:c3e521df8b2b498a7a682e7e18676771cb80c6b75b8699af886b2d554ce40151
```

The TLS-verified official registry resolved `3.14-slim-trixie` and
`3.14.8-slim-trixie` to that index; response bytes independently hashed to the
reported digest. Its linux/amd64 manifest is:

```text
sha256:65a94bb37b630c482dfd31e5fb9b449cb26c31eab1b7a125cd6bd624acfe3b30
```

The Dockerfile retains index pinning. Other architectures are unqualified. The
workflows build on `ubuntu-latest` without a wider architecture matrix; their
Bookworm-only base assertions need the corresponding narrow Trixie update.

## Aruba comparison and overlay

Aruba's clean local main was inspected read-only at
`ac6cbe52419f20b535460c0c68669be8ef58222f`. Its current Dockerfile pins Python
3.14.7 / Debian 13.7:

```text
python:3.14.7-slim-trixie@sha256:51dafde81dbdb6ebde285137a295cf18a47ca95234fe388a343719cb97305b3d
```

Choose the newer official base: it preserves the common Trixie family, updates
Python, and already includes the OpenSSL versions Aruba adds. Do not retain the
older digest solely for alignment or copy Aruba's full seven-package overlay.

| Package | Clean selected base | Qualified worker |
| --- | --- | --- |
| libpcre2-8-0 | 10.46-1~deb13u2 | 10.46-1~deb13u3 |
| gzip | 1.13-1+deb13u1 | unchanged |
| libsqlite3-0 | 3.46.1-7+deb13u2 | unchanged |
| libssl3t64, openssl, openssl-provider-legacy | 3.5.7-1~deb13u3 | unchanged |
| perl-base | 5.40.1-6+deb13u1 | unchanged |

The old worker's PCRE2 `10.42-1+deb12u1` blocks on CVE-2026-103111. The clean
Trixie base also reports it. Authenticated apt metadata offered
`10.46-1~deb13u3` from `trixie-security`; installation succeeded, agreeing with
[Debian's CVE record](https://security-tracker.debian.org/tracker/CVE-2026-103111).
Replace the Bookworm overlay with this sole exact Trixie upgrade. No other apt
upgrade is needed by the gate. No package/source discrepancy remains. Remove
this overlay in a future reviewed base refresh once the upstream includes it.
The [official Python page](https://hub.docker.com/_/python) confirms the current
tag family; exact-image inventory and scans established these package choices.

## Vulnerability evidence

The unchanged repository comparator and main's existing exception registry
were used. No worker exception applied or was added. All scans target
linux/amd64 and HIGH/CRITICAL; lower severities are outside this gate.

| Worker / its exact upstream | Introduced | Inherited | Fixable unexcepted | Removed | Exceptions | Result |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Bookworm | 0 | 63 (58 HIGH, 5 CRITICAL) | 1 | 4 | 0 | BLOCKED |
| Trixie | 0 | 44 (44 HIGH, 0 CRITICAL) | 0 | 5 | 0 | PASS |

The before scan used the existing local worker
`local/unifi-cert-renewer:ls147-review-renewer`, not a fresh main build. Its
inventory confirms the old runtime and PCRE2 overlay; this fresh scan reproduces
the supplied CI's 63 findings and sole PCRE2 blocker. The clean selected Trixie
upstream has 49 HIGH findings, five with fixes. The derivative has **no
CVE-2026-103111 finding**. Removed upstream-only findings are:

| Finding | Upstream package/version | Removal |
| --- | --- | --- |
| CVE-2026-103111 | libpcre2-8-0 10.46-1~deb13u2 | exact Debian security upgrade |
| CVE-2025-47273 | setuptools 70.3.0 | existing pip/ensurepip removal |
| GHSA-6v7p-g79w-8964 | msgpack 1.1.2 | existing pip/ensurepip removal |
| CVE-2026-97687, CVE-2026-97689 | urllib3 2.7.0 | existing pip/ensurepip removal |

The Python findings belong to upstream installer tooling; runtime dependencies
were not upgraded. Debian upgrade inheritance adjustments: 0. A passing gate is
**not a clean-image claim**, a reachability mitigation, or risk acceptance.

Pinned scanner (Trivy 0.74.0) and comparator container:

```text
ghcr.io/aquasecurity/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969
python:3.14.7-slim-trixie@sha256:cad9a2c871761c413caa6fdd6441c783451e740a48aaeba60ae62a8b53525ef6
```

| Snapshot | Schema | Updated UTC | Downloaded UTC |
| --- | ---: | --- | --- |
| OS | 2 | 2026-10-04 08:52:32 | 2026-10-04 11:54:29 |
| Java | 1 | 2026-10-04 01:44:08 | 2026-10-04 12:01:44 |

Database file SHA-256 values (OS, then Java):

```text
f684c51b045908383ef92b1ad55b1723e6f9db6cad7479602f3f51dae6b3c179
b0e4a6342d1d9d86aa4df7ec193aaa6cb2cd02841895c8d17ff6137ae43321db
```

Both images were scanned offline with identical repository scan flags and
snapshots. The OS hash was identical before/after all four old/new image scans.
The complete wrapper also passed against the candidate with retained OS/Java
snapshots. No worker contains Java packages. External local harnesses retained
evidence, reused snapshots, and explicitly mounted the host's existing public
CA bundle for verified database downloads. Repository scanner code, flags,
policy, and exception data were unchanged.

## All remaining inherited findings

All 44 are HIGH OS findings on `os:debian/13.7`, with canonical
`package@version` identities, empty package paths, and **no scanner-reported
fixed version**. Each CVE/package pairing counts separately.

| CVE | Packages | Installed version | Count |
| --- | --- | --- | ---: |
| CVE-2025-69720 | libncursesw6, libtinfo6, ncurses-base, ncurses-bin | 6.5+20250216-2 | 4 |
| CVE-2026-16742 | libsystemd0, libudev1 | 257.13-1~deb13u1 | 2 |
| CVE-2026-54369 | libacl1 | 2.3.2-2+b1 | 1 |
| CVE-2026-9538 | perl-base | 5.40.1-6+deb13u1 | 1 |

Each of CVE-2026-76642, CVE-2026-78408, CVE-2026-78409, and
CVE-2026-78410 affects every package below (nine per CVE, 36 total):

| Packages | Installed version |
| --- | --- |
| bsdutils | 1:2.41.5-0+deb13u1 |
| login | 1:4.16.0-2+really2.41.5-0+deb13u1 |
| libblkid1, liblastlog2-2, libmount1, libsmartcols1, libuuid1, mount, util-linux | 2.41.5-0+deb13u1 |

## Checks actually run

- Full suites: **1,637 passed each** on Python 3.12.14, 3.14.7, and candidate
  Trixie/Python 3.14.8, including real keytool with generated disposable
  keystores, cryptographic/certificate/TLS tests, and synthetic inspection,
  due/not-due renewal, and failure paths. Final patch: full 3.12.14 and 3.14.8
  suites also passed.
- Worker packaging and restricted entrypoint smoke passed: UID/GID 1000:1000,
  non-root, executor implementation absent, expected usage/exit response, and
  no pip/ensurepip/setuptools/pkg_resources/msgpack. Runtime imports and package
  metadata passed with hash-locked cryptography 50.0.1, cffi 2.1.1, pycparser
  3.0. Existing source/icon/GPL-3.0-only labels remain.
- Files remain root-owned and non-writable by the worker. Runtime checks used
  read-only root, all capabilities dropped, no-new-privileges, pids limit 64,
  a 16 MiB noexec/nosuid/nodev tmpfs, and no network. No exposed ports, image
  volumes, Docker socket, private-key mount, or new worker privilege mechanism.
- Compose v5.5.1 resolution with exact CI fixture values, deployment semantic
  validation, OPNsense ACL validation, and existing mount contracts passed.
- Two-container lock contention passed: real `renew` returned exact busy JSON
  and exit 75; after holder termination another worker reacquired the same
  host inode. A scoped disposable root helper provisioned/stat'ed/cleaned only
  synthetic test state because host sudo needs an unavailable password. The
  unchanged contention script and worker restrictions were retained.
- Ruff lint/format, Bash/s6 syntax, ShellCheck, Hadolint 2.15.1, actionlint
  1.7.12, changed-document Markdown lint, both actual workflow upstream-resolution
  shell blocks, and `git diff --check` passed. Locks were unchanged, not regenerated.

## Limitations and final security review

The unmodified candidate build reached pip, then failed certificate verification
at `files.pythonhosted.org` because container trust lacks the host's corporate
CA. An external temporary build context installed existing public wheels with
`--no-index` and unchanged `--require-hashes`, removing the wheel directory.
The local qualification image ID is:

```text
sha256:1d8e9504ddec4eb5f452ca570f8783fe71654abd8fc2f9f0844129899898a5be
```

This is not a published identity. Normal CI still needs to build the unmodified
online Dockerfile. No TLS bypass or trust change was added to the worker.

The combined packaging script passed its worker half, then stopped because the
existing local ls147 vendor fixture lacks `renewal_policy.py` and `unifi_tls.py`.
Worker checks also passed separately; no vendor assertion was weakened and no
vendor image rebuilt or changed. Fresh combined validation remains for CI.
Initial test-only tmpfs execution errors were resolved with executable synthetic
fixture tmpfs; missing GnuPG was added only to disposable test tooling. Production
retains noexec tmpfs and excludes test/installer tooling.

The patch changes no runtime application logic, key/certificate semantics,
configuration, locks, vendor image, or exception registry. Digest pinning,
verified TLS, existing-key continuity, UID 1000, least privilege, and worker/
executor separation remain. Exact apt remediation fails closed if unavailable;
future scanner findings can change and CI must repeat the gate before merge.
No commit, push, PR, tag, remote workflow/settings change, image publication,
release, deployment, or production/device operation occurred.

Local evidence is retained under `/tmp/unifi-trixie-evidence-20261004`, with raw
scan/cache artifacts at `/tmp/cert-renewer-trivy.cNE99K` and
`/tmp/cert-renewer-trivy.rBPhE8`. These are temporary review artifacts, not durable
release evidence or repository fixtures.
