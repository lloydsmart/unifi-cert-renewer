# UniFi vendor finding decision: 9 November 2026

## Decision and exact scope

On 9 November 2026 Lloyd Smart, as owner and reviewer, explicitly approved
the 38 reviewed inherited Java findings, including the unknown MongoDB
Snappy risk, until **00:00 UTC on 16 November 2026 (exclusive)**.
The decision renews 32 expired records and adds six exact findings.
There are 27 HIGH and 11 CRITICAL findings across 14 affected JAR paths.

The scope remains `linux/amd64` and this upstream index digest:

```text
lscr.io/linuxserver/unifi-network-application@sha256:5f5e76c95b5bd4becb0cdb1b96ef53a468e75ca0f7a096ca5c24fc30998b382a
```

The [registry](../.security/container-exceptions.json) preserves each exact
result class/type/target, advisory ID, package name/ID, installed version,
path, scanner severity and fixed-version string. Existing identifiers and
finding metadata remain unchanged. The new findings are inherited from the
vendor image, not introduced by the dependency or operating-system updates.

The authorisation covers applying this decision, security documentation,
validation, a signed commit and a push to PR #95. It does not approve a merge,
deployment, production configuration change or automatic exception renewal.
[Issue #63](https://github.com/lloydsmart/unifi-cert-renewer/issues/63) remains
the remediation tracker.

## Evidence and remediation constraint

The retained fresh 9 November scans compare the seven-package-remediated
derivatives at source commit `dd4c8b86ad78d256a6066efcef8d7d4a26449b6a`
with their exact upstream images, using pinned Trivy 0.74.0 and a shared
database snapshot. The UniFi comparison has zero introduced findings,
38 inherited Java findings and 13 removed upstream findings.
The renewer has zero introduced findings, 47 inherited findings without a
reported fix and 10 removed upstream findings.

Separate scans of `10.6.106-ls151`, `10.6.109-ls152` and `10.6.109-ls153`
retain all 38 Java findings. All 14 affected JAR hashes match the qualified
baseline. This establishes no scanner remediation from those updates, not
equivalence of every application behaviour. No individually replaced JAR
bundle has been qualified. Temporary acceptance preserves the existing
certificate-renewal integration while vendor remediation remains outstanding.

The 32 prior applicability assessments were reassessed against their exact
current scanner identities and earlier finding reviews. This was not a new
full runtime audit of all 32. The
[18 October decision](vendor-finding-review-2026-10-18.md) links earlier evidence
and is superseded only for current acceptance and expiry.

## Six new findings

### CVE-2026-102554: Guava deserialization allocation

No native Java deserialization call was found in the searched UniFi
namespaces, and no external reference to the named affected Guava collection
classes was found. Serialized class names need not appear in application
code; frameworks, reflection and other namespaces remain uncertain.
Ordinary JSON use alone does not establish this native deserialization path.
The scanner's HIGH severity is retained.
[Vendor advisory](https://github.com/google/guava/security/advisories/GHSA-xxph-c9ww-hj94).

### CVE-2026-55276: Tomcat effective configuration logging

The advisory concerns incomplete logged effective configuration, not itself
a demonstrated request-authorization bypass. No external `logEffectiveWebXml`
reference was found; live configuration and audit practice were not inspected.
The scanner's CRITICAL severity is retained despite Apache's lower rating.

### CVE-2026-65637: Tomcat HTTP/2 strict SNI validation

UniFi connector bytecode conditionally registers HTTP/2. Effective connector,
TLS termination, strict SNI and host-routing settings remain unverified.
HTTP/2 must not be dismissed as absent. Scanner CRITICAL is retained.

### CVE-2026-53404: Tomcat rewrite conditions

No external `RewriteValve` reference or bundled rewrite configuration was
found in the inspected JARs. Filesystem overrides and runtime registration
remain unverified. Scanner HIGH is retained.

The three Tomcat assessments use
[Apache's security record](https://tomcat.apache.org/security-10.html).
Differences from vendor severity do not override scanner policy.

### CVE-2026-93451: Snappy typed-array heap corruption

No reference to the six affected typed-array methods was found outside
Snappy in the 65,337 inspected classes from 146 JARs; parsing had zero errors.
Observed application uses were byte-array or stream operations.
Reflection and dynamic loading remain unexcluded. The heap-corruption
finding retains HIGH severity.
[Vendor advisory](https://github.com/xerial/snappy-java/security/advisories/GHSA-gwq9-9ffj-mvrv).

### CVE-2026-108106: Snappy output allocation

The inform request reader caps input at 10 MiB. Its packet parser bounds
payload length against the actual packet, and its decompression helper calls
`isValidCompressedBuffer` before either Snappy branch. The default-auth-key
branch additionally caps output at 10 MiB. These controls mitigate the
malformed-length mechanism on the observed route; valid compressed data
can still expand substantially on the other branch. No general availability
guarantee is claimed.

The bundled MongoDB driver defaults to an empty compressor list. Its receive
selector rejects Snappy when absent from that configured list. If configured,
`SnappyInputStream` allocates internally before the driver copies into the
destination buffer. Outer message and compressed-chunk limits do not establish
a decompressed-output bound. Both synchronous and asynchronous receive paths
use this ordering. The receive guard uses the configured compressor map;
a statement that compression was not negotiated is insufficient evidence.

Bounded offline checks used the exact bundled Snappy 1.1.10.8, MongoDB driver
core 5.1.4 and BSON 5.5.2 libraries. The inform validator rejected a malformed
control before decompression. Actual MongoDB decompression allocated about
1 MiB despite a 16-byte destination, then rejected the input. A four-byte
compressed-chunk limit also allowed a 1 MiB internal allocation. The actual
driver selector rejected Snappy with an empty list and selected it when
explicitly configured, without opening a connection or handshake.

Tests used network-disabled disposable containers with a 64 MiB Java heap
and 256 MiB container memory; test output sizes were limited to 1 MiB.
No production service, configuration, credentials or keystore was accessed.
The full servlet and live database connection were not executed.
[Vendor allocation advisory](https://github.com/xerial/snappy-java/security/advisories/GHSA-q233-g92q-qxp6).

The effective production MongoDB compressor list is **unknown**. Lloyd Smart
expressly accepted that uncertainty and the possible database-peer availability
risk until expiry. Ordinary inform traffic does not establish control of
database replies. No disabled production Snappy setting or verified peer-trust
boundary is claimed.

Check the effective compressor list as soon as server access is available and
before expiry, accounting for `MONGO_CONNECTION_OVERRIDE` before `db.mongo.uri`.
Do not disclose connection strings or credentials. Enabled Snappy requires
immediate re-review and consideration of a separately authorised mitigation
or vendor fix; no such production change has been made.

## Exposure, expiry and follow-up

The operator confirmed unchanged internal LAN/VPN restrictions for management,
guest-portal and device-facing endpoints, and no known incident. These are
operator reports, not independently verified controls or proof of safety.
Compromised permitted clients, devices, peers and stored content remain
relevant. None of the findings is declared inapplicable or non-exploitable.

Remove exceptions when a qualified vendor fix eliminates the constraint.
Re-review on image, package, platform, scanner identity, exposure, applicability
or incident changes, and before expiry. Introduced findings always block.
Expired, malformed or mismatched records fail closed. No blanket suppression,
severity downgrade or automatic renewal is authorised.

## Validation boundary

The approved registry is validated against both retained 9 November scan pairs
using the unchanged pinned comparator. Policy validation is separate from
human risk acceptance and from GitHub CI. Existing boundary tests cover
expiry, exact-scope changes and continued blocking of introduced findings.
No new build, release or production qualification is implied by this
documentation-only and exception-registry change.

## Accepted finding inventory

The registry is authoritative for every full identity and literal fix string.

| Advisory | Exception identifier | Severity |
| --- | --- | --- |
| CVE-2026-54512 | EX-UNIFI-20260926-002 | HIGH |
| CVE-2026-54513 | EX-UNIFI-20260926-003 | HIGH |
| CVE-2025-66021 | EX-UNIFI-20260926-004 | HIGH |
| CVE-2026-54399 | EX-UNIFI-20260926-005 | HIGH |
| CVE-2026-54428 | EX-UNIFI-20260926-006 | HIGH |
| CVE-2026-41293 | EX-UNIFI-20260926-007 | CRITICAL |
| CVE-2026-43512 | EX-UNIFI-20260926-008 | CRITICAL |
| CVE-2026-43515 | EX-UNIFI-20260926-009 | CRITICAL |
| CVE-2026-65182 | EX-UNIFI-20260926-010 | CRITICAL |
| CVE-2026-65905 | EX-UNIFI-20260926-011 | CRITICAL |
| CVE-2026-68525 | EX-UNIFI-20260926-012 | CRITICAL |
| CVE-2026-41284 | EX-UNIFI-20260926-013 | HIGH |
| CVE-2026-42498 | EX-UNIFI-20260926-014 | HIGH |
| CVE-2026-43513 | EX-UNIFI-20260926-015 | HIGH |
| CVE-2026-42198 | EX-UNIFI-20260926-016 | HIGH |
| CVE-2026-54291 | EX-UNIFI-20260926-017 | HIGH |
| CVE-2026-41695 | EX-UNIFI-20260926-018 | HIGH |
| CVE-2026-41716 | EX-UNIFI-20260926-019 | HIGH |
| CVE-2026-41717 | EX-UNIFI-20260926-020 | HIGH |
| CVE-2026-41850 | EX-UNIFI-20260926-021 | HIGH |
| CVE-2026-41842 | EX-UNIFI-20260926-022 | HIGH |
| CVE-2026-41845 | EX-UNIFI-20260926-023 | HIGH |
| CVE-2026-8763 | EX-UNIFI-20260926-024 | CRITICAL |
| CVE-2026-13506 | EX-UNIFI-20260926-025 | HIGH |
| CVE-2026-68497 | EX-UNIFI-20260930-026 | HIGH |
| CVE-2026-91776 | EX-UNIFI-20260930-027 | HIGH |
| CVE-2026-91777 | EX-UNIFI-20260930-028 | HIGH |
| CVE-2026-89407 | EX-UNIFI-20261002-029 | HIGH |
| CVE-2026-89425 | EX-UNIFI-20261002-030 | HIGH |
| CVE-2026-68494 | EX-UNIFI-20261004-031 | HIGH |
| CVE-2026-47884 | EX-UNIFI-20261018-032 | CRITICAL |
| CVE-2026-47890 | EX-UNIFI-20261018-033 | CRITICAL |
| CVE-2026-102554 | EX-UNIFI-20261109-034 | HIGH |
| CVE-2026-55276 | EX-UNIFI-20261109-035 | CRITICAL |
| CVE-2026-65637 | EX-UNIFI-20261109-036 | CRITICAL |
| CVE-2026-53404 | EX-UNIFI-20261109-037 | HIGH |
| CVE-2026-108106 | EX-UNIFI-20261109-038 | HIGH |
| CVE-2026-93451 | EX-UNIFI-20261109-039 | HIGH |
