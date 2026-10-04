# UniFi vendor finding decision: 4 October 2026

## Reviewed scope and decision

The 3 October requalification compared the retained `10.6.106-ls147` image
with its exact upstream index digest on `linux/amd64`:

```text
lscr.io/linuxserver/unifi-network-application@sha256:5f5e76c95b5bd4becb0cdb1b96ef53a468e75ca0f7a096ca5c24fc30998b382a
```

The derivative had zero introduced and 30 inherited HIGH/CRITICAL UniFi JAR
findings. Twenty-nine existing exceptions matched the fresh scanner findings
exactly. One fixable inherited finding, `CVE-2026-68494`, blocked the comparison.
The reviewed `ls148` derivative had the same 30 inherited findings and offered
no remediation for this set. Lloyd Smart, as owner and reviewer, decided on
4 October to retain `ls147`, renew the 29 matching exceptions, and separately
accept the exact CVE finding until **00:00 UTC on 12 October 2026**. This
decision does not authorize an `ls148` deployment or digest migration.

## Scanner identity change

The scanner now reports `CVE-2026-68494` for Jackson Core 2.21.2 where the
earlier review recorded `GHSA-r7wm-3cxj-wff9`. The CVE Project record cites the
FasterXML GHSA as its source advisory for the same issue. This is a change in
scanner identity, with no new evidence of UniFi reachability. The old
`EX-UNIFI-20260926-001` record is retired from the active registry. Its
[earlier review](vendor-finding-review-2026-09-17.md) remains historical evidence,
as does the prior registry revision in Git. The new, independently approved
`EX-UNIFI-20261004-031` record matches only the CVE. It retains the reviewed
`lang-pkgs` / `jar` / `Java` identity, package
`com.fasterxml.jackson.core:jackson-core`, empty package ID, path
`usr/lib/unifi/lib/local/jackson-core-2.21.2.jar`, installed version `2.21.2`,
`HIGH` severity, and exact fixed-version text `2.18.8, 2.21.4`.

## Risk and follow-up

These 30 records are temporary accepted risks, not findings of
non-exploitability. Attacker-controlled JSON would need to arrive in chunks at
Jackson Core's nonblocking integer parser for the newly identified CVE.
UniFi use of that parser for untrusted streams has neither been demonstrated
nor excluded. The operator reports management, guest-portal, and device-facing
endpoints restricted to trusted LAN/VPN users and devices. That restriction
has not been independently verified and is not an advisory-specific parser
fix. Malicious or compromised permitted clients and devices remain relevant.

No advisory-specific mitigation has been verified. Preserve and verify the
reported LAN/VPN restriction. Prefer a vendor-supported fixed UniFi image;
do not independently replace bundled JARs without separate qualification.
Re-review on changes to image, package, scanner identity, exposure, or
applicability, and before expiry. [Issue #63](https://github.com/lloydsmart/unifi-cert-renewer/issues/63)
tracks remediation. The exact image comparator must still confirm a passing
scan against the retained upstream before a release or deployment.
