# UniFi Jackson Core finding review: 2 October 2026

## Reviewed scope

This temporary acceptance applies only to the pinned LinuxServer UniFi Network
Application `10.6.106-ls147` index digest on `linux/amd64`:

```text
lscr.io/linuxserver/unifi-network-application@sha256:5f5e76c95b5bd4becb0cdb1b96ef53a468e75ca0f7a096ca5c24fc30998b382a
```

Both inherited HIGH findings are in Jackson Core 2.21.2 at
`usr/lib/unifi/lib/local/jackson-core-2.21.2.jar`, JAR SHA-256
`12e8655b100267b44d0f14d01b1f5082a5105e616174dc4307be1a761e92407b`.
The static review scanned 146 UniFi JARs and 65,337 classes with no class parse
errors. This evidence describes the reviewed bundle, not a demonstrated live
exploit route. The earlier [30 September review](vendor-finding-review-2026-09-30.md)
and its 28 exception records remain unchanged.

## CVE-2026-89407: numeric-looking JSON strings

The exact scanner identity is `lang-pkgs` / `jar` / `Java`, package
`com.fasterxml.jackson.core:jackson-core`, empty package ID, the JAR path above,
and installed version `2.21.2`. The exact scanner `FixedVersion` string is
`2.18.11, 2.21.7, 2.22.3`.

Exploitation requires a numeric-looking, attacker-controlled JSON string to
reach an affected Jackson numeric deserializer and
`NumberInput.looksLikeValidNumber`, with availability impact from excessive CPU
or request-worker use. Positive static evidence is that bundled Jackson
Databind directly calls this helper from numeric deserializers and UniFi uses
Jackson for JSON input. UniFi's explicit Spring MVC mapper disables
`ALLOW_COERCION_OF_SCALARS`, reducing the ordinary REST binding route. No
attacker-controlled route to the helper was demonstrated. Other mappers,
indirect binding, and runtime configuration were not excluded.

## CVE-2026-89425: DataInput-backed parsing

The exact scanner identity is `lang-pkgs` / `jar` / `Java`, package
`com.fasterxml.jackson.core:jackson-core`, empty package ID, the same JAR path
and installed version. The exact scanner `FixedVersion` string is
`2.21.7, 2.22.3, 2.18.11`; its order is retained for literal matching.

Exploitation requires malformed input to reach Jackson's vulnerable
`DataInput`-backed parser, with possible memory exhaustion or an out-of-memory
failure. The parser is present, and Jackson Databind has `DataInput` overloads.
The complete static JAR review found no UniFi application reference to
`DataInput`, `DataInputStream`, or Jackson's `DataInput` parser overload.
Observed UniFi JSON factory calls use `InputStream`, `String`, or byte arrays.
The Databind overloads establish capability only. Reflection, framework
dispatch, generated code, and other indirect routes remain unexcluded.

## Exposure, decision, and follow-up

The operator reports management, guest-portal, and device-facing endpoints
restricted to trusted LAN/VPN users and devices. This was not independently
verified and is not an advisory-specific mitigation. Malicious or compromised
permitted clients or devices remain possible sources of affected input.

On 2026-10-02 Lloyd Smart, as owner and reviewer, explicitly accepted both
inherited HIGH findings temporarily as `EX-UNIFI-20261002-029` and
`EX-UNIFI-20261002-030`. This is **risk acceptance, not a finding of
non-applicability or proof of non-exploitability**. The two records retain exact
scanner identity, severity, and `FixedVersion` strings and expire at **00:00 UTC
on 2026-10-05** under the comparator's exclusive expiry rule. Existing exception
expiries are not extended. [Issue #63](https://github.com/lloydsmart/unifi-cert-renewer/issues/63)
tracks remediation.

Preserve and verify the reported LAN/VPN restriction; do not broaden endpoint
exposure. Monitor CPU and request-worker exhaustion for `CVE-2026-89407` and
memory and out-of-memory failures for `CVE-2026-89425`. Prefer a
vendor-supported fixed UniFi image. Do not independently replace bundled JARs.
Re-review immediately if upstream image, package, platform, exposure, scanner
identity, or applicability changes, and before expiry. These records do not
authorize a release or deployment. The image-level comparator must still verify
the exact scanner state; this document does not claim a local comparator pass.
