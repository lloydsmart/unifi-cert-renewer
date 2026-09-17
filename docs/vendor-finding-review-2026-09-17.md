# UniFi vendor finding review - 17 September 2026

First-pass static review of the 23 supplied image findings. **All 23 need review**;
none is established as exploitable in this deployment, and none is established
as inapplicable. Confidence is medium for this unresolved verdict. Scanner
severity is preserved. The maintainer separately approved the exact exceptions
recorded under the decision below; this is risk acceptance, not a finding that
the affected features are safe or unreachable.

The operator reports management, guest-portal, and device-facing endpoints are
restricted to trusted LAN/VPN users and devices. That reduces direct exposure;
it is not a verified firewall assessment or protection against compromised LAN
devices, permitted users, malicious peer responses, or stored content.

The [latest LinuxServer release](https://github.com/linuxserver/docker-unifi-network-application/releases/tag/10.6.106-ls146)
was checked on 17 September and remains the pinned `10.6.106-ls146`. A supported
newer bundle has not been established. Replacing individual JARs would require
separate vendor compatibility and runtime qualification; no such replacement
or vulnerability suppression was performed.

## Per-finding evidence and next step

Each row retains one supplied finding. The review rank orders plausible request
paths before findings needing several additional configuration or peer-control
conditions. It is a review queue, not a claim of demonstrated exploitability.
The affected package/version/path and scanner fix strings remain in the
[original inventory](vendor-image-findings-2026-09-17.json).

### GHSA-r7wm-3cxj-wff9: Jackson async parser

Verdict: **needs review** (medium confidence). Review rank: 3.

Required condition: Chunked untrusted JSON reaches a non-blocking number parser.

Missing evidence: Whether UniFi uses the async parser for untrusted streams.

[Primary advisory](https://github.com/FasterXML/jackson-core/security/advisories/GHSA-r7wm-3cxj-wff9)

### CVE-2026-54512: Jackson generic type validation

Verdict: **needs review** (medium confidence). Review rank: 7.

Required condition: Untrusted polymorphic type IDs reach generic type resolution with an approved outer
container.

Missing evidence: Polymorphic typing, validator configuration, and useful gadget reachability.

[Primary advisory](https://github.com/FasterXML/jackson-databind/security/advisories/GHSA-j3rv-43j4-c7qm)

### CVE-2026-54513: Jackson array type validation

Verdict: **needs review** (medium confidence). Review rank: 8.

Required condition: Untrusted array types reach a validator that permits array subtypes without checking
elements.

Missing evidence: Whether allowIfSubTypeIsArray and attacker-controlled type IDs are used.

[Primary advisory](https://github.com/FasterXML/jackson-databind/security/advisories/GHSA-rmj7-2vxq-3g9f)

### CVE-2025-66021: HTML sanitizer

Verdict: **needs review** (medium confidence). Review rank: 12.

Required condition: Attacker HTML reaches a policy permitting noscript and style with text inside style.

Missing evidence: Exact UniFi sanitizer policy and subsequent browser rendering.

[Primary advisory](https://github.com/OWASP/java-html-sanitizer/security/advisories/GHSA-g9gq-3pfx-2gw2)

### CVE-2026-54399: HttpCore HTTP/1 parser

Verdict: **needs review** (medium confidence). Review rank: 9.

Required condition: Untrusted HTTP messages with excessive headers reach the affected parser.

Missing evidence: Whether UniFi uses affected client or server paths and effective header limits.

[Primary advisory](https://lists.apache.org/thread/zmxh1pl2zohov5ntdh4lt85gfrlchgpy)

### CVE-2026-54428: HttpCore HTTP/2 decoder

Verdict: **needs review** (medium confidence). Review rank: 10.

Required condition: Untrusted HPACK blocks reach the decoder before settings acknowledgement applies limits.

Missing evidence: HTTP/2 use, peer trust, and header-limit timing in UniFi.

[Primary advisory](https://lists.apache.org/thread/5zjp8vczvxq19pw2rvhs21q446bhl0sd)

### CVE-2026-41293: Tomcat HTTP/2 headers

Verdict: **needs review** (medium confidence). Review rank: 1.

Required condition: Untrusted HTTP/2 headers reach servlet code without expected protocol validation.

Missing evidence: Whether HTTP/2 is enabled and downstream code relies on rejected header values.

[Primary advisory](https://tomcat.apache.org/security-10.html)

### CVE-2026-43512: Tomcat DIGEST authentication

Verdict: **needs review** (medium confidence). Review rank: 16.

Required condition: A request for an unknown realm user reaches Tomcat DIGEST authentication.

Missing evidence: Whether UniFi uses Tomcat DIGEST and the relevant realm.

[Primary advisory](https://tomcat.apache.org/security-10.html)

### CVE-2026-43515: Tomcat method constraints

Verdict: **needs review** (medium confidence). Review rank: 14.

Required condition: Requests reach overlapping method constraints for the same extension pattern.

Missing evidence: Exact servlet security constraints and authorization coverage.

[Primary advisory](https://tomcat.apache.org/security-10.html)

### CVE-2026-65182: Tomcat path constraints

Verdict: **needs review** (medium confidence). Review rank: 15.

Required condition: A longer path constraint precedes a more restrictive sub-path constraint.

Missing evidence: Effective security-constraint ordering and alternate authorization controls.

[Primary advisory](https://tomcat.apache.org/security-10.html)

### CVE-2026-65905: Tomcat DIGEST replay

Verdict: **needs review** (medium confidence). Review rank: 18.

Required condition: Captured DIGEST requests satisfy a boundary nonce-count window.

Missing evidence: DIGEST use and attacker ability to obtain an authenticated request.

[Primary advisory](https://tomcat.apache.org/security-10.html)

### CVE-2026-68525: Tomcat FORM authentication

Verdict: **needs review** (medium confidence). Review rank: 17.

Required condition: FORM login redirects interact with different POST and GET authorization.

Missing evidence: FORM authenticator use and per-method security constraints.

[Primary advisory](https://tomcat.apache.org/security-10.html)

### CVE-2026-41284: Tomcat WebDAV

Verdict: **needs review** (medium confidence). Review rank: 20.

Required condition: Untrusted LOCK or PROPFIND request bodies reach an enabled WebDAV servlet.

Missing evidence: Whether WebDAV is shipped and enabled on any supported UniFi endpoint.

[Primary advisory](https://tomcat.apache.org/security-10.html)

### CVE-2026-42498: Tomcat WebSocket client

Verdict: **needs review** (medium confidence). Review rank: 21.

Required condition: An authenticated outgoing WebSocket request follows a cross-host redirect.

Missing evidence: Use of the affected client and attacker influence over redirect targets.

[Primary advisory](https://tomcat.apache.org/security-10.html)

### CVE-2026-43513: Tomcat LockOutRealm

Verdict: **needs review** (medium confidence). Review rank: 19.

Required condition: Case variants of a username reach a case-insensitive backing realm behind LockOutRealm.

Missing evidence: Exact realm chain and case handling; a login page alone does not prove this setup.

[Primary advisory](https://tomcat.apache.org/security-10.html)

### CVE-2026-42198: PostgreSQL SCRAM iterations

Verdict: **needs review** (medium confidence). Review rank: 22.

Required condition: An attacker-controlled PostgreSQL server supplies an excessive SCRAM iteration count.

Missing evidence: Whether the bundled JDBC driver is used and which database endpoints it can contact.

[Primary advisory](https://github.com/pgjdbc/pgjdbc/security/advisories/GHSA-98qh-xjc8-98pq)

### CVE-2026-54291: PostgreSQL channel binding

Verdict: **needs review** (medium confidence). Review rank: 23.

Required condition: A TLS-intercepting peer supplies a certificate algorithm with no channel-binding hash.

Missing evidence: JDBC use, TLS trust, channelBinding=require, and interception feasibility.

[Primary advisory](https://github.com/pgjdbc/pgjdbc/security/advisories/GHSA-j92g-9f8w-j867)

### CVE-2026-41695: Spring property path resolution

Verdict: **needs review** (medium confidence). Review rank: 5.

Required condition: Untrusted property strings reach MappingContext against nested models or many invalid
paths.

Missing evidence: UniFi callers, accepted property paths, and effective input limits.

[Primary advisory](https://spring.io/security/cve-2026-41695/)

### CVE-2026-41716: Spring property lookup cache

Verdict: **needs review** (medium confidence). Review rank: 4.

Required condition: HTTP-supplied names reach unfiltered PropertyPath lookups or supported web bindings.

Missing evidence: Querydsl or projected-payload binding use and filtering in UniFi.

[Primary advisory](https://spring.io/security/cve-2026-41716/)

### CVE-2026-41717: Spring MongoDB query binding

Verdict: **needs review** (medium confidence). Review rank: 6.

Required condition: Untrusted input reaches an annotated query with a capture-all placeholder.

Missing evidence: Exact Query or Aggregation annotations and endpoint-to-query input handling.

[Primary advisory](https://spring.io/security/cve-2026-41717/)

### CVE-2026-41850: Spring expression evaluation

Verdict: **needs review** (medium confidence). Review rank: 11.

Required condition: User-controlled expressions reach the SpEL evaluator.

Missing evidence: Whether untrusted expressions are evaluated and with what restrictions.

[Primary advisory](https://spring.io/security/cve-2026-41850/)

### CVE-2026-41842: Spring versioned static resources

Verdict: **needs review** (medium confidence). Review rank: 2.

Required condition: Requests reach filesystem resources with versioned-resource support enabled.

Missing evidence: Static-resource configuration and exposure in the vendor application.

[Primary advisory](https://spring.io/security/cve-2026-41842/)

### CVE-2026-41845: Spring JavaScript escaping

Verdict: **needs review** (medium confidence). Review rank: 13.

Required condition: Untrusted text is escaped by JavaScriptUtils then embedded in browser JavaScript.

Missing evidence: Exact escaping call sites and output context in UniFi templates.

[Primary advisory](https://spring.io/security/cve-2026-41845/)

## Evidence boundaries

The image dependency is established by `deployment/unifi/Dockerfile:3-4` and
the exact scanned JAR inventory. The overlay runs the Python executor alongside
the vendor service. It does not establish servlet authentication, Jackson parser
selection, Spring query annotations, sanitizer policies, or JDBC call paths.
At the start of this static review, the repository security policy required
review of inherited findings and recorded no accepted vulnerability exceptions.
The subsequent explicit risk decision is recorded below and in `SECURITY.md`. The relevant boundary is a permitted
network client or peer reaching the vendor Java application; its full path is
unproven for every row.

A bundled PostgreSQL driver is not evidence that UniFi exposes PostgreSQL to
clients. Likewise, an ordinary login page does not establish Tomcat DIGEST or
FORM authentication. These are proof gaps, not reasons to dismiss the findings.

Apache rates several Tomcat issues below the scanner labels; severity differences
do not waive policy. For the newest listed Tomcat fixes, use released `10.1.59`
as the library reference: `10.1.58` did not pass its release vote. This still
does not establish a vendor-supported UniFi bundle with that library. See the
[Apache release/security record](https://tomcat.apache.org/security-10.html).

HttpCore advisory mail pages were not retrievable through the browser; their
specific claims remain sourced from the supplied scanner descriptions, with
the [Apache security model](https://hc.apache.org/security.html) as additional
context. No test, application, build, or exploit was run for this static triage.

## Approved temporary risk decision

On 2026-09-17 Lloyd Smart explicitly approved the prepared 23 exceptions until
1 October 2026, with Lloyd Smart as owner and reviewer. The applied
[registry](../.security/container-exceptions.json) is byte-for-byte the approved
proposal. Every entry names the exact advisory, package, installed version,
location, severity, fix metadata, Linux/amd64 platform, and pinned upstream.

Expiry is 00:00 UTC on 2026-10-01. The gate will fail closed after expiry or if
scope changes; old-version approvals cannot carry through a package upgrade.
The [PR](https://github.com/lloydsmart/unifi-cert-renewer/pull/57) tracks this
review and the requirement for vendor-supported remediation or a new explicit
decision before expiry. No automatic renewal is authorized.

No advisory-specific mitigation is established. Preserve the operator-reported
LAN/VPN restriction. Compromised or malicious permitted clients, devices,
peers, and stored content remain residual risks. Review immediately if exposure
changes. There is no blanket inherited exemption. The approval does not authorize
deployment, migration, release, or merging the PR.
