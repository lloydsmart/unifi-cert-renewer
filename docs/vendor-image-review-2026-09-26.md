# Vendor image review: 26 September 2026

CI and future release builds are being updated to LinuxServer UniFi Network
Application `10.6.106-ls147`, pinned to the multi-platform index:

    lscr.io/linuxserver/unifi-network-application@sha256:5f5e76c95b5bd4becb0cdb1b96ef53a468e75ca0f7a096ca5c24fc30998b382a

The selected Linux amd64 manifest is:

    sha256:59b41343c8ef2381181bb10e93c2b4d11501125731ed7ce25b35df46951ac9d2

This replaces the previously reviewed `10.6.106-ls146` baseline at:

    lscr.io/linuxserver/unifi-network-application@sha256:7f15f34937ce928b36d915a0ad4ab6a915a0c34e87affa10c47d09ad1341b848

The qualification in this document covers Linux amd64 only. It does not
establish arm64 compatibility.

## Scope and application payload

Both images contain UniFi Network Application `10.6.106`.

A complete SHA-256 inventory of the UniFi JAR payload under `/usr/lib/unifi`
contained 146 JARs in each image. The inventories were byte-identical. The
LinuxServer rebuild therefore changes the surrounding container/runtime image,
not the reviewed UniFi Java application payload.

The upstream operating-system package inventories also contain the same 159
packages, with no packages added or removed. Only two installed package versions
changed:

- `openjdk-25-jre-headless`:
  `25.0.4+7-1~26.04` -> `25.0.4.1+1-1~26.04.4`
- `perl-base`:
  `5.40.1-7ubuntu0.2` -> `5.40.1-7ubuntu0.3`

Both images identify as Ubuntu 26.04.1 LTS. The Java runtime moved from OpenJDK
25.0.4 to 25.0.4.1.

Neither upstream image contains Python. The certificate-renewer derivative
continues to install the Ubuntu Python 3.14 runtime as part of its overlay build.

## Derivative validation

The certificate-renewer UniFi derivative built successfully from the exact
`ls147` digest above.

The independent renewer image also built successfully from its existing pinned
base and dependency locks.

The repository's existing container packaging validation passed for both images:

    Validated renewer and UniFi image packaging boundaries

This confirms the reviewed packaging invariants, including removal of the unused
Pebble supervisor, remain satisfied by the `ls147` derivative.

No production image was published by this review.

## Vulnerability comparison

The repository's pinned Trivy/comparator policy was run against the locally
built `ls147` derivative and the exact `ls147` upstream using the same downloaded
database snapshots for both sides of the comparison.

Before applying reviewed exceptions, the result was:

    Introduced derivative-only HIGH/CRITICAL findings: 0
    Inherited HIGH/CRITICAL findings requiring impact review: 25
    Unexcepted fixable inherited HIGH/CRITICAL findings: 25
    Removed upstream-only HIGH/CRITICAL findings: 0
    Inherited Debian findings carried through package upgrades: 0
    Reviewed inherited finding exceptions applied: 0

The 25 inherited finding identities are exactly the same set observed against
the current `ls146` baseline: the 23 findings reviewed on 17 September plus two
subsequently reported Bouncy Castle findings:

- `CVE-2026-8763`, Critical, `org.bouncycastle:bcprov-jdk18on` 1.84,
  fixed in 1.85.
- `CVE-2026-13506`, High, `org.bouncycastle:bcprov-jdk18on` 1.84,
  fixed in 1.85.

No new HIGH/CRITICAL vulnerability identity is introduced by moving from
`ls146` to `ls147`.

## Bouncy Castle applicability review

LinuxServer `ls147` still contains:

    bcprov-jdk18on-1.84.jar
    bcpkix-jdk18on-1.84.jar
    bcutil-jdk18on-1.84.jar

Static inspection established that UniFi does use Bouncy Castle. Its internal
code registers `BouncyCastleProvider` using `Security.addProvider`, and uses
Bouncy Castle APIs for certificate construction/signing, X.500 handling, and
PEM parsing.

For `CVE-2026-8763`, repository review found no non-Bouncy-Castle application
class directly referencing the affected Bouncy Castle PKIX certificate-path
validator or its name-constraint implementation. Non-Bouncy-Castle PKIX users
identified in the image use the standard Java `CertPathValidator` APIs. This
reduces demonstrated reachability but does not prove the vulnerable path is
unreachable; reflection, dynamic provider selection, or other runtime-only paths
remain possible.

For `CVE-2026-13506`, the vulnerable ASN.1 implementation is present and
Bouncy Castle is genuinely used by UniFi. However, the whole-classpath static
search found no non-Bouncy-Castle application reference to `ASN1InputStream`,
`LazyEncodedSequence`, or `X509CRLHolder`. Indirect reachability through higher
level Bouncy Castle parsing APIs remains possible. This review therefore does
not claim non-exploitability.

Direct replacement of bundled Bouncy Castle JARs has not been qualified. A
vendor-supported update to Bouncy Castle 1.85 or later remains preferred.

## Temporary exception decision

The previous 23 reviewed finding identities remain unchanged because the UniFi
JAR payload is byte-identical to `ls146`.

On 26 September 2026 Lloyd Smart explicitly reviewed the exact `ls147`
`linux/amd64` baseline and approved fresh temporary exceptions for all 25
inherited fixable HIGH/CRITICAL findings, including the two Bouncy Castle
findings above.

The refreshed exceptions:

- are scoped to the exact `ls147` digest;
- are scoped to `linux/amd64`;
- retain exact package, version, path, advisory, severity, and fix metadata;
- are owned and reviewed by Lloyd Smart;
- expire on 1 October 2026;
- do not extend the previous expiry;
- do not apply to introduced findings; and
- are tracked by [issue #63][tracking].

With those 25 exact exceptions applied, the real image-policy scan produced:

    Introduced derivative-only HIGH/CRITICAL findings: 0
    Inherited HIGH/CRITICAL findings requiring impact review: 25
    Unexcepted fixable inherited HIGH/CRITICAL findings: 0
    Removed upstream-only HIGH/CRITICAL findings: 0
    Inherited Debian findings carried through package upgrades: 0
    Reviewed inherited finding exceptions applied: 25
    PASS: no introduced or unexcepted fixable inherited HIGH/CRITICAL findings were found.

The comparator's exception-policy test suite also passed:

    146 passed

## Exposure and limitations

The operator reports management, guest-portal, and device-facing endpoints are
restricted to trusted LAN/VPN users and devices. That restriction was not
independently verified by this review. Compromised or malicious permitted
clients, devices, peers, or stored content remain residual risks.

This review does not establish:

- full UniFi application readiness;
- MongoDB/database migration compatibility;
- device adoption or device compatibility;
- production certificate renewal;
- arm64 compatibility;
- production deployment safety; or
- exploitability or non-exploitability of the inherited findings.

No production deployment, release, migration, tag, image publication, commit,
or merge is authorised by this review.

The prior 17 September evidence remains historical context and is not rewritten
by this refresh. See the [previous vendor-image review][previous-review] and
[previous per-finding review][previous-findings].

[tracking]: https://github.com/lloydsmart/unifi-cert-renewer/issues/63
[previous-review]: vendor-image-review-2026-09-17.md
[previous-findings]: vendor-finding-review-2026-09-17.md
