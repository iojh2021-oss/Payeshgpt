# PayeshGPT — Android Security Lab

PayeshGPT is a defensive, read-only Android security assessment prototype for devices and lab images the operator is authorized to inspect.

## Implemented in this repository

- Minimal Android application written in Kotlin with a Persian-language interface.
- Launcher-app inventory using Android's package-visibility-limited APIs.
- Rust evidence-correlation library with SHA-256 helpers, reference-hash comparison, conservative assessments, and JSON reports.
- JNI entry point connecting the Android app to the Rust assessment engine.
- CI workflows for Rust unit tests and an Android ARM64 debug APK build/artifact.

## Current limitations — important

- The separately supplied `payesh.zip` application has **not yet been merged** into this scaffold. The current Android UI is a minimal integration shell, not a complete import of that app.
- The current screen lists launcher-visible apps; it does not yet scan APK contents, dynamically inspect every installed package, or monitor network traffic.
- The report currently passes an empty evidence list to Rust. It must correctly remain **inconclusive**; it is not a malware scan result.
- The Android build workflow has been committed, but its first green run and APK artifact must be checked in GitHub Actions before claiming the APK builds successfully.
- No rootkit detection claim is made. A normal Android app cannot freely read kernel memory or protected partitions. Rust/C/C++ do not bypass the Android sandbox.
- Hardware-backed attestation is not implemented. Verified Boot and Play Integrity/Key Attestation data must be validated and interpreted according to their documented trust model; locally reported values are not automatically independent proof.

## Planned next milestones

1. Import and review the original Android project from `payesh.zip`, preserving its useful UI and working features.
2. Add tests for archive import, Android package metadata collection, hash-manifest provenance, and JNI integration.
3. Implement permission/app metadata analysis with clear evidence sources and false-positive handling.
4. Add optional user-consented network metadata monitoring only after its scope and privacy behavior are documented.
5. Integrate supported platform integrity signals and separate local observations from independently validated evidence.
6. Verify CI logs and distribute an APK only after the build and runtime smoke tests pass.

## Build and test

Rust tests:

```sh
cd native/payesh-core
cargo test
```

Android ARM64 debug APK is built by the `Android APK` GitHub Actions workflow. The workflow uploads `app-debug.apk` as the `payeshgpt-debug-apk` artifact when successful.

## Security semantics

- Missing evidence means `inconclusive`, not safe.
- A hash mismatch is a finding, not proof of malware or a rootkit.
- A local observation is not automatically independent evidence.
- A clean result only means the supplied evidence did not trigger a finding; it is not a guarantee that the device is uncompromised.
