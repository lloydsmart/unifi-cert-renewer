# Vendor image review: 17 September 2026

CI and future release builds use LinuxServer UniFi Network Application
`10.6.106-ls146`, pinned to the multi-platform index:

```text
lscr.io/linuxserver/unifi-network-application@sha256:7f15f34937ce928b36d915a0ad4ab6a915a0c34e87affa10c47d09ad1341b848
```

This replaces `10.3.58-ls128` at digest
`sha256:274311cdf64294f217f74004571d214f605ca85ea01002a84bde9eaf5130e43a`.
The selected amd64 manifest is
`sha256:00d4d3f4751f39b7969e2d28316fcc2c7e74ddad2855cb9f67160744c142e25c`.
The local validation below covers Linux amd64 only; the multi-platform index
alone does not establish arm64 compatibility.

## Scope and compatibility

The [upstream release][release] supplies UniFi 10.6.106. Its Ubuntu 26.04 base
uses Java 25; the executor overlay installs distro Python 3.14. The shared source
retains Python 3.12 compatibility and the existing two-version test matrix.

LinuxServer runs its services through s6. Its Ubuntu base also includes the
unused `/usr/bin/pebble` service supervisor. The derivative removes that binary
and packaging checks reject its return. No UniFi JAR is replaced, and no
certificate, private-key, executor protocol, or database operation is changed.
The vendor [base-image recipe][base] defines `/init` as its entrypoint.

The startup-diagnostic unit test now injects failure at `recover_startup`, which
both entrypoints invoke. This makes the test independent of the existence of
an empty `/config` directory in a container.

## Same-database scan

Trivy 0.74.0 used vulnerability data updated 2026-09-17 14:01 UTC and Java data
updated 2026-09-17 01:10 UTC. Findings below are component/version instances,
not established remotely exploitable vulnerabilities.

| Image | High | Critical | Findings with reported fixes |
| --- | ---: | ---: | ---: |
| Previous application derivative | 26 | 7 | 33 |
| New upstream / unmodified executor derivative | 25 | 6 | 31 |
| New derivative with unused Pebble removed | 17 | 6 | 23 |

The unmodified new derivative introduced no findings relative to its exact new
upstream. However, that upstream added eight High Go standard-library findings
in Pebble relative to the previous application image. Removing the unused
supervisor eliminates those eight findings. The final derivative has no
introduced findings relative to its exact new upstream, and no newly reported
advisory/package identities relative to the previous derivative. That latter
comparison deliberately ignores version/path changes and is additional triage
evidence, not a replacement for the strict upstream comparator.

The update removes ten finding rows overall, including the Bouncy Castle
Critical finding and the previous OpenSSL findings. It is not a clean-image
claim: **23 fixable inherited findings remain**, including six Critical Tomcat
rows. They are not accepted vulnerability exceptions or deployment approval.

The [remaining finding inventory](vendor-image-findings-2026-09-17.json) records
each advisory, version, path, severity and reported fix. It is evidence, not a
scanner suppression list.

Remaining affected components include Tomcat 10.1.54, Jackson 2.21.2, the OWASP
HTML sanitizer, Apache HttpCore 5.3.6, PostgreSQL JDBC 42.7.10, and Spring
components. Scanner severity must not be lowered merely because [Apache's
ratings][tomcat] differ. Feature reachability in a real UniFi deployment remains
unverified. Fixed upstream library versions are not proof that replacement JARs
are compatible with UniFi.

## Disposable evidence and limits

Local builds used the exact pinned upstream and unchanged hashed runtime locks.
Because Linux package-index TLS validation is blocked locally, disposable build
copies used hash-verified wheels fetched over verified HTTPS through Windows.
These acquisition-only adaptations are outside the repository. No image was
published by this assessment.

All 817 tests passed on Python 3.12.14 and on the candidate's distro Python
3.14.4, including the synthetic Java keystore tests. Ruff, workflow lint, shell
checks, Markdown, and positive/negative packaging checks passed.

A networkless `/init` boot used fresh temporary configuration, runtime, and
secret files. LinuxServer generated a synthetic keystore inside its own
container. Startup reached Java/executor eligibility, with executor socket
`root:984` mode `0660`, admin lock `root:root` mode `0600`, and keystore
`1000:1000` mode `0600`. A separate corrupt synthetic journal caused recovery to
fail closed before Java or executor service startup.

The only database listener accepted and closed loopback TCP connections to
exercise the initialization reachability check. It was not MongoDB. This proves
service ordering and file/socket boundaries, not database migration, full UniFi
readiness, device compatibility, or a production renewal. No production data,
credentials, keystore, host Docker socket, published ports, or external network
was available to the boot containers. Their synthetic keystores stayed inside
the disposable owning container and were destroyed with it.

Before an operator deploys a new release, review the [vendor setup guidance][docs]
and release changes against the installed UniFi/database versions. Establish a
consistent application/database recovery point while preserving the existing
private key within its owning storage boundary. A database migration may prevent
rollback by changing only the image digest. Deployment and migration acceptance
remain separate, explicitly authorized work.

## Remaining audit work

Track the remaining exact vendor advisories and their exposure. Prefer a
compatible maintained vendor update. Any temporary acceptance must name the
exact image, package/version and advisory, mitigation, owner and expiry, and be
reviewed explicitly. No acceptance is introduced here.

The common image policy still needs implementation: block introduced
High/Critical findings regardless of available fixes, and fixable inherited
findings without a reviewed time-bounded exception. The current comparator's
passing result does not mean those remaining findings meet that future policy.

[release]: https://github.com/linuxserver/docker-unifi-network-application/releases/tag/10.6.106-ls146
[base]: https://github.com/linuxserver/docker-baseimage-ubuntu/blob/resolute/Dockerfile
[tomcat]: https://tomcat.apache.org/security-10.html
[docs]: https://docs.linuxserver.io/images/docker-unifi-network-application/
