# UniFi vendor finding decision for 20 November 2026

Lloyd Smart, owner and reviewer, approved temporary acceptance of 38 inherited
Java-library findings on 20 November 2026. All 38 records expire at
**00:00 UTC on 27 November 2026, exclusive**. The previous acceptance expired
at 00:00 UTC on 16 November. Its finding-specific assessments and targeted
MongoDB/Snappy evidence remain available in the
[9 November review](vendor-finding-review-2026-11-09.md).

The decision covers the 27 HIGH and 11 CRITICAL records in the
[exception registry](../.security/container-exceptions.json) for
`linux/amd64` and the UniFi `10.6.106-ls147` upstream index digest
`sha256:5f5e76c95b5bd4becb0cdb1b96ef53a468e75ca0f7a096ca5c24fc30998b382a`.
Every advisory, scanner target, package identity, installed version, path,
severity and fixed-version string matched its earlier record. The comparator
continues to block introduced findings and enforce the exclusive expiry.

## Vendor evidence and OpenJDK fix

Trivy 0.74.0 compared the rebuilt images with their exact upstreams using
the same 20 November vulnerability databases. The ls155 candidate at index
`sha256:053a608b25f578bb92b7b4f59e3835f6cc6dd0c7500c30b24ac0e27e1742ab20`
retained all 38 Java findings. Its 14 affected JARs matched the ls147 copies
byte for byte. Temporary acceptance preserves the existing integration while
awaiting a qualified vendor bundle. Individual JAR replacements still require
qualification.

The initial UniFi build also inherited `CVE-2026-114938` in OpenJDK.
The rebuilt image upgrades `openjdk-25-jre-headless` to Ubuntu's fixed
version, `25.0.5.1+2-1~26.04.1`. Build and packaging checks enforce that
minimum. All 146 UniFi application JARs matched the qualified upstream
by path and SHA-256. The fresh scan confirmed removal of the OpenJDK
finding. [Ubuntu security notice](https://ubuntu.com/security/notices/USN-9157-1)

| Final derivative | Introduced | Inherited with a reported fix | Inherited without a reported fix | Removed upstream |
| --- | ---: | ---: | ---: | ---: |
| UniFi | 0 | 38 | 0 | 14 |
| Renewer | 0 | 0 | 47 | 6 |

The locally qualified UniFi manifest was
`sha256:ccca9b8555ffece36e46b1cbf6790ebfc082e383f391296651505408c3d488db`.
Each of the Python 3.12, 3.14 and 3.15 suites passed 2,353 tests. The 3.14
test image used the rebuilt OpenJDK 25 runtime for disposable keystore tests
covering CSR generation, certificate import and recovery.

## Exposure and follow-up

On 20 November the operator reported unchanged LAN/VPN restrictions on
management, guest-portal and device-facing endpoints and no known incident.
The assessment relies on those reports. Compromised permitted clients,
devices, peers and stored content remain potential sources of exposure.

The effective production MongoDB compressor list remains **unknown**.
Lloyd Smart expressly accepted the resulting availability risk under
`CVE-2026-108106`. If Snappy is configured, a malicious or compromised
database peer could cause excessive allocation before the driver's
destination limit takes effect. Check the effective compressor list as soon
as server access permits and before expiry, accounting for
`MONGO_CONNECTION_OVERRIDE` taking precedence over `db.mongo.uri`.
Report only compressor names or status. Reopen the decision immediately if
Snappy is enabled.

Review the set before expiry and whenever the image, packages, platform,
scanner identity, exposure, applicability or incident history changes.
Remove each exception once a qualified fix resolves it. Track remediation in
[issue #63](https://github.com/lloydsmart/unifi-cert-renewer/issues/63).
