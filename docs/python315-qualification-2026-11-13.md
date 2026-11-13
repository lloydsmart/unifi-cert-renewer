# Python 3.15 qualification — 13 November 2026

## Scope

This change extends Dependabot PR #96 into a coordinated Python 3.15 upgrade.
It moves the renewer, development tools, canonical dependency compiler,
dependency scanner and container-report comparator to Python 3.15. The UniFi
executor continues to use its reviewed distribution Python 3.14 runtime.
Shared-source compatibility remains covered on Python 3.12 and 3.14, alongside
the new Python 3.15 test job.

The selected renewer upstream is:

```text
python:3.15-slim-trixie@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928
```

The downloaded Linux amd64 image reports Python 3.15.2. Deployment and release
validation continue requiring the exact supported tag and a SHA-256 digest.
The finished renewer must report Python 3.15 and exclude `pip`, `ensurepip`,
`setuptools`, `pkg_resources` and `msgpack`.

## Compatibility correction

Qualification reproduced a scanner startup failure on Python 3.15:
`ModuleNotFoundError: No module named 'sre_constants'`. The locked
`pip-api==0.0.34` imported that removed module through its vendored parser.

The security input now requires `pip-api>=0.0.35`; its generated lock selects
0.0.35. That [released upstream fix](https://github.com/di/pip-api/releases/tag/0.0.35)
supports Python 3.15 and removes the affected vendored parser. `pip-audit`
remains pinned at 2.10.1. No compatibility shim or scanner suppression is used.

All four locks were regenerated through `scripts/compile-requirements.sh`
with Python 3.15.2, pip 26.3 and pip-tools 7.6.2. Two consecutive canonical
passes were byte-identical. The only dependency-version change is pip-api
0.0.34 to 0.0.35; runtime, development and compiler dependency versions remain
unchanged. All four generated headers now identify Python 3.15.

## Local results

| Check | Result |
| --- | --- |
| Full suite, Python 3.12.14 | 2,129 passed; includes both Java integration tests |
| Full suite, Python 3.14.8 | 2,129 passed; includes both Java integration tests |
| Full suite, Python 3.15.2 | 2,129 passed; includes both Java integration tests |
| Hash-required runtime/development installs and `pip check` | Passed on all three runtimes |
| Canonical lock regeneration | Two byte-identical passes |
| All four dependency audits on Python 3.15.2 | No known vulnerabilities found |
| Ruff and formatting | Passed; 81 Python files already formatted |
| Workflow, Markdown and shell lint | Passed |
| OPNsense ACL and Compose deployment validation | Passed |
| Full reachable Git history and working-tree secret scans | No leaks found |
| Two-container lifecycle contention and lock release | Passed |
| Renewer and UniFi packaging boundaries | Passed |
| Container vulnerability comparisons | Both passed the existing policy; details below |

The Python suites ran with networking disabled and generated disposable
cryptographic test material. Java integration used OpenJDK 17 for Python 3.12
and OpenJDK 21 for Python 3.14/3.15. No production device or credential was used.

Both image comparisons found zero introduced HIGH/CRITICAL findings and zero
unexcepted fixable inherited HIGH/CRITICAL findings. The renewer retains 47
inherited findings with no scanner-listed fix, removes seven upstream findings,
and uses no exceptions. The UniFi image retains the same 38 exactly approved
inherited findings. These results are policy passes, not claims that either
image is free of vulnerabilities or that the inherited findings are harmless.
The unfixed renewer findings remain reported for impact review under the
[container image policy](container-image-policy.md).

## Build-environment limitation

The unchanged production Dockerfiles reached their hash-required pip install
steps locally, but package downloads failed certificate verification on the
corporate network. The official base images do not trust the local corporate
issuing CA.

For local container qualification only, temporary copies of the Dockerfiles
add a required BuildKit secret mount to the existing pip install step and set
`PIP_CERT` for that command. The host's established CA bundle is supplied through
that mount. Certificate verification and package hashes remain mandatory.
The bundle is not copied into a layer; the finished renewer was checked for
absence of both the secret file and a persistent `PIP_CERT` environment setting.
The repository Dockerfiles have no corporate-CA change.

The local packaging results therefore apply to those explicitly identified
qualification builds. A successful GitHub Actions run of the unchanged
production recipes and CodeQL is still required before merge. Local results
do not claim remote CI, release qualification or live renewal acceptance.

## Security and release boundaries

No vulnerability exception, expiry, TLS policy, private-key boundary,
container privilege or release approval rule changes. The 38 existing UniFi
exceptions remain limited to their exact reviewed identities and expire at
2026-11-16 00:00 UTC exclusively. They are not extended by this upgrade.

No commit, push, workflow rerun, merge, release or production deployment was
performed during this local qualification stage. Evidence logs and temporary
build recipes are retained separately in the local qualification evidence
directory.
