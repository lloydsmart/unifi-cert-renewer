# UniFi vendor finding review: 30 September 2026

## Reviewed image and scanner evidence

The pinned LinuxServer `10.6.106-ls147` upstream remains:

    lscr.io/linuxserver/unifi-network-application@sha256:5f5e76c95b5bd4becb0cdb1b96ef53a468e75ca0f7a096ca5c24fc30998b382a

Its Linux amd64 manifest is
`sha256:59b41343c8ef2381181bb10e93c2b4d11501125731ed7ce25b35df46951ac9d2`.
The reviewed `10.6.106-ls148` index is
`sha256:5d288401f8bce9561caa64939ef4188bbb5a3e0f5bc159a833fdabd9afbc531a`;
its Linux amd64 manifest is
`sha256:41c0db8f1715f79c78dadfac713e7c395815c675b53fe650a792e35e933ec099`.

Both images carry UniFi Network Application 10.6.106. SHA-256 comparison found
all 146 UniFi JARs byte-identical. The reviewed vendor OS-package layer changes
in `ls148` are `libsqlite3-0` from `3.46.1-9ubuntu0.2` to
`3.46.1-9ubuntu0.3`, and `rust-coreutils` from `0.8.0-0ubuntu3` to
`0.10.0-1ubuntu2~26.04.1`. They remove none of these 26 findings. Moving to
`ls148` would change the digest and invalidate all `ls147` exceptions without
resolving this finding set.

The fresh `ls147` derivative/upstream scan review found 19 HIGH and 7 CRITICAL
findings, all 26 inherited and zero introduced HIGH/CRITICAL. The 25 previously
excepted findings retained their exact scanner identity, package path, installed
version, severity, and `FixedVersion` text. One newly reported inherited HIGH,
`CVE-2026-68497`, was unexcepted before this decision. The scan JSON artifacts
are not retained in this worktree; the image-level comparator must run again in
CI against exact images before any release decision. This record does not claim
a comparator pass against the updated registry.

## CVE-2026-68497 applicability

The affected bundled component is Jackson databind 2.21.2 at
`usr/lib/unifi/lib/local/jackson-databind-2.21.2.jar`, SHA-256
`8c982f01f148d805f0aaac2339011244757e0df7c6ff8951f2fa3f433b8ed849`.
The scanner reports `lang-pkgs` / `jar` / `Java`, package
`com.fasterxml.jackson.core:jackson-databind`, empty package ID, HIGH severity,
and exact `FixedVersion` text `2.18.10, 2.21.6, 2.22.2`.

Exploitation would require attacker-controlled JSON string data to bind through
Jackson to `javax.xml.datatype.Duration` or `XMLGregorianCalendar`, causing
excessive CPU or memory use. Static review found the affected implementation
present, but no direct UniFi application-class reference to those XML datatype
types and no concrete affected binding route through REST/API, inform,
WebSocket, configuration import, or persisted data. Dynamic binding,
reflection, runtime mapper configuration, and other indirect routes remain
unexcluded. This finding is **not established as inapplicable**.

The operator reports management, guest-portal, and device-facing endpoints
restricted to trusted LAN/VPN users and devices. The restriction was not
independently verified and is not an advisory-specific mitigation. Malicious or
compromised permitted clients and devices remain a risk.

## Qualifications for future bundles

Scanner `FixedVersion` strings are exact exception-matching data; release
qualification must also consider vendor history. Apache reports Tomcat 10.1.58
was not released, so 10.1.59 was the first released build containing certain
fixes. The fix for `CVE-2026-41293` had a later regression fixed in 10.1.60.
This review does not edit scanner `FixedVersion` fields to match that history.

Bouncy Castle has later releases, but UniFi still bundles 1.84 and independent
replacement of those JARs is unqualified. UniFi genuinely uses Bouncy Castle;
the affected PKIX route remains unproved for `CVE-2026-8763`, and indirect
affected ASN.1 parsing remains possible for `CVE-2026-13506`. The other 23
prior findings retain the applicability uncertainty documented in the
[17 September finding review](vendor-finding-review-2026-09-17.md) and
[26 September vendor-image review](vendor-image-review-2026-09-26.md). The
renewed per-record prerequisites are in the
[exception registry](../.security/container-exceptions.json).

## Temporary owner decision

On 2026-09-30 Lloyd Smart, as owner and reviewer, explicitly approved temporary
risk acceptance for the 25 existing exact `ls147` findings and newly reported
`CVE-2026-68497`. The 26 records are scoped to the pinned index digest,
`linux/amd64`, and each exact scanner finding identity, severity, and fix text.
They expire at **00:00 UTC on 2026-10-05** under the comparator's exclusive
expiry-date rule. Introduced findings cannot be excepted. This decision is
risk acceptance, not remediation, proof of non-exploitability, or release or
deployment approval.

No advisory-specific mitigation has been verified. Preserve the
operator-reported restricted exposure, prefer a vendor-supported fixed image,
and do not independently replace bundled JARs. Re-review immediately if the
upstream image, package, platform, exposure, scanner identity, or applicability
changes. There is no automatic extension: a further exception requires another
explicit decision before expiry. [Issue #63](https://github.com/lloydsmart/unifi-cert-renewer/issues/63)
tracks remediation.

## Subsequent Ubuntu OpenSSL remediation

After the 26-finding owner decision above, the next CI scan reported three new
inherited, fixable HIGH findings for CVE-2026-84782 in the pinned `ls147`
upstream: `libssl3t64`, `openssl`, and `openssl-provider-legacy` at
`3.5.5-1ubuntu3.5`. These findings were not part of the owner's accepted 26.
[Ubuntu USN-8847-1](https://ubuntu.com/security/notices/USN-8847-1) identifies
`3.5.5-1ubuntu3.6` as the supported Ubuntu 26.04 fix floor for the OpenSSL
source package.

The UniFi derivative now explicitly upgrades only those three installed
packages from the existing Ubuntu repositories. Its build and container
packaging checks require each installed version to be at least
`3.5.5-1ubuntu3.6` using `dpkg` version comparison. The exact-pinned `ls147`
local build reached the package layer and installed `3.5.5-1ubuntu3.6` for
all three packages from Ubuntu `resolute-updates/main`. The subsequent pip
dependency step did not complete locally because TLS verification of
`files.pythonhosted.org` failed; a complete derivative image and image scan
therefore remain to be confirmed by CI.

No exception was added for CVE-2026-84782. This remediation does not revise
the owner's acceptance of the other 26 findings. If the patched derivative
has no CVE-2026-84782 rows, the unchanged comparator reports the three
unpatched upstream rows as removed upstream-only findings.

## Subsequent Jackson findings and owner decision

After the earlier 26-finding owner decision, a later scan reported two additional
inherited HIGH findings in the pinned `10.6.106-ls147` upstream on
`linux/amd64`: `CVE-2026-91776` and `CVE-2026-91777`. Neither was covered by
that earlier decision. Fresh review reproduced both against the pinned index
digest `sha256:5f5e76c95b5bd4becb0cdb1b96ef53a468e75ca0f7a096ca5c24fc30998b382a`.
Both are in bundled Jackson databind 2.21.2 at
`usr/lib/unifi/lib/local/jackson-databind-2.21.2.jar` (JAR SHA-256
`8c982f01f148d805f0aaac2339011244757e0df7c6ff8951f2fa3f433b8ed849`).
The latest reviewed LinuxServer `10.6.106-ls148` retains the same 146 UniFi
JARs byte for byte and the same current HIGH/CRITICAL scanner identities. No
reviewed vendor-supported fixed LinuxServer image, standalone UniFi release,
or derivative OS-package remediation was identified. Independent Jackson JAR
replacement is unqualified.

For `CVE-2026-91776`, UniFi classes include name-based polymorphism using
`JsonTypeInfo.Id.NAME` with `defaultImpl`, including examples under
`com.ubnt.ace.ws` and another application class. ObjectMapper and HTTP
message-converter references are present. If attacker-influenced distinct type
IDs reach the relevant model and long-lived deserializer, process-lifetime
retention could cause heap growth or out-of-memory failure. No concrete
attacker-controlled REST, WebSocket, import, or device route to those models
was demonstrated; whether a route shares the deserializer and whether it is
unauthenticated remain unproved.

For `CVE-2026-91777`, static review found no direct UniFi application-class
reference to `@JsonIdentityInfo`, though the annotation is present in Jackson
and a dependent schema module. Runtime mix-ins, indirect framework use,
generated models, and affected endpoint shapes were not excluded. If
attacker-influenced JSON reaches an identity-enabled collection or map,
reverse-order unresolved object references could cause quadratic CPU work.
No concrete affected UniFi input route was established.

On 2026-09-30 Lloyd Smart explicitly approved temporary exact acceptance of
both findings as `EX-UNIFI-20260930-027` and `EX-UNIFI-20260930-028`, tracked
by [issue #63](https://github.com/lloydsmart/unifi-cert-renewer/issues/63).
The registry now has 28 inherited vendor-image exceptions: 21 HIGH and
7 CRITICAL. All retain the exact pinned digest and `linux/amd64` scope and
expire at **00:00 UTC on 2026-10-05**; the expiry was not extended.
The operator reports management, guest-portal, and device-facing endpoints
restricted to trusted LAN/VPN users and devices, which was not independently
verified. Preserve and verify that restriction, do not broaden exposure,
monitor upstream fixes and service memory, and re-review on upstream, package,
platform, exposure, scanner identity, or applicability change and before
expiry. This decision is risk acceptance, not remediation or a finding of
non-exploitability.
