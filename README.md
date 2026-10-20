# PayeshGPT — Android Security Lab

PayeshGPT is being developed as a **defensive, read-only Android security assessment tool** for authorized devices and lab images.

## Current repository status
This repository was empty when the project was inspected. The Kotlin Android application supplied separately as `payesh.zip` has not yet been imported into this repository. Do not treat this scaffold as a completed APK or as proof that kernel rootkits can be detected.

## Engineering goals
- Preserve useful Android-side app, permission, file-hash, and network-monitoring capabilities when the existing app is imported.
- Add a native Rust analysis core for deterministic, testable integrity-evidence evaluation.
- Keep device collection read-only and least-privilege by default.
- Correlate multiple evidence sources instead of treating one property or scan result as definitive.
- Clearly report **confirmed**, **suspicious**, **not assessed**, and **inconclusive** states.
- Use Android Verified Boot / Key Attestation where supported, while distinguishing locally reported values from remotely validated evidence.
- Add reproducible CI tests and an audit-friendly JSON report format.

## Important limits
An ordinary Android application cannot freely read kernel memory, inspect every protected partition, or reliably detect every kernel-level implant. Native C/C++/Rust code does not bypass Android's app sandbox. Rooted lab builds can expose additional evidence, but a compromised kernel can falsify local observations. High-confidence validation should use trusted boot-chain signals and, where appropriate, evidence verified off-device.

## Planned architecture
- **Android app (Kotlin):** permissions, package inventory, user consent, UI, VPN-based network metadata, report export.
- **Native engine (Rust):** parsers, hashing, integrity-evidence correlation, deterministic risk findings.
- **Optional C/C++ adapters:** only where NDK interfaces or existing libraries justify them.
- **Independent validation:** CI tests, known-good reference manifests, and supported hardware-backed attestation.

## Status
Initial repository bootstrap only. Native engine, Android integration, and APK build validation are not complete yet.