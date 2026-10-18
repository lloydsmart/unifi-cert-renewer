# UniFi vendor finding decision: 18 October 2026

## Reviewed scope and evidence

This decision applies only to LinuxServer UniFi Network Application
`10.6.106-ls147` on `linux/amd64`, at the exact upstream index digest:

```text
lscr.io/linuxserver/unifi-network-application@sha256:5f5e76c95b5bd4becb0cdb1b96ef53a468e75ca0f7a096ca5c24fc30998b382a
```

The 17 October requalification reported 32 inherited UniFi Java findings:
23 HIGH and 9 CRITICAL, with zero derivative-introduced findings and eight
remediated upstream findings. Thirty findings retained the exact scanner
identities already present in the exception registry. The two new findings
were `CVE-2026-47884` and `CVE-2026-47890`.

The prior temporary evidence directory was unavailable when this decision was
implemented on 18 October. Its `SHA256SUMS.txt` and the proposed matrix,
registry, review, and validation log could therefore not be authenticated or
used. A fresh local diagnostic scan with the repository-pinned Trivy 0.74.0
image, a shared pair of database snapshots, the exact upstream image, and the
curl-remediated derivative independently reproduced the reported counts:
32 inherited Java findings, zero introduced findings, and eight removed
upstream findings. The existing comparator, using the updated exception registry, matched all 32 records exactly.
This local result is not a substitute for GitHub CI qualification.

## New exact scanner identities

Both new records retain these common identity fields:

- result class/type/target: `lang-pkgs` / `jar` / `Java`;
- package: `org.springframework:spring-webmvc`;
- package ID: empty;
- package path:
  `usr/lib/unifi/lib/local/spring-webmvc-6.2.18.jar`;
- installed version: `6.2.18`;
- severity: `CRITICAL`;
- exact fixed-version text: `7.0.9`.

The records are `EX-UNIFI-20261018-032` for `CVE-2026-47884` and
`EX-UNIFI-20261018-033` for `CVE-2026-47890`. They are distinct exact
exceptions; neither transfers an earlier acceptance or advisory identity.

### Spring MVC applicability

#### CVE-2026-47884 — XSLT view rendering

The affected Spring framework functionality is present. Static analysis did
not demonstrate a UniFi XsltView resolver/configuration or a qualifying
catch-all handler performing implicit view-name rendering. Dynamic context
and bean registration, profiles, reflection, and indirect configuration
remain unverified.

#### CVE-2026-47890 — SSE view-fragment rendering

The affected Spring framework functionality is present. Static analysis did
not demonstrate a UniFi SSE view-fragment pathway carrying attacker-controlled
content to another user. Indirect runtime registration, content negotiation,
and effective data flows remain unverified.

Neither finding is established as inapplicable or non-exploitable. Both
retain the scanner's CRITICAL severity in their exact exception records,
regardless of differences from Spring's advisory severity.

## Decision and residual risk

On 18 October 2026 Lloyd Smart, as owner and reviewer, explicitly approved a
seven-day temporary acceptance of all 32 exact inherited findings. The
exceptions expire exclusively at **00:00 UTC on 25 October 2026**. There is no
automatic extension, and the decision does not apply to another image digest,
platform, package identity, path, version, severity, fixed-version string, or
introduced finding.

The maintainer confirmed that UniFi management, guest-portal, and device-facing
endpoints remain restricted to internal networks. That exposure restriction is
important context, but it is not an advisory-specific fix. Malicious or
compromised permitted clients, devices, peers, and stored content remain
relevant. The finding-specific routes and effective UniFi configurations remain
uncertain. This is acceptance of residual risk, not a determination that any
finding is inapplicable or non-exploitable.

Prefer a vendor-supported fixed image and do not independently replace bundled
Java libraries. Re-review immediately if the upstream image, package, platform,
exposure, scanner identity, severity, fixed-version metadata, or applicability
changes. A fresh explicit decision is required before expiry. Introduced or
unexpected findings remain blocking, and expired, malformed, incomplete, or
mismatched exception data fails closed. [Issue #63](https://github.com/lloydsmart/unifi-cert-renewer/issues/63)
continues to track remediation.
