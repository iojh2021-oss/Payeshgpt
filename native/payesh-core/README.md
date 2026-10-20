# payesh-core

A small Rust library for deterministic correlation of Android security evidence.

## Scope
- SHA-256 for bytes supplied by a caller.
- Comparison of observed hashes with an explicitly supplied reference map.
- Conservative correlation of integrity and behavior evidence.
- JSON-serializable reports and unit tests.

## Security semantics
- Missing observations are `unavailable`, not safe.
- A local observation is not automatically independent evidence.
- A hash mismatch is a finding, not proof of a rootkit.
- A clean result means only that the supplied evidence did not trigger a finding.
- This crate does not read protected Android partitions, inspect kernel memory, root a device, or bypass Android's sandbox.

For high-assurance lab assessments, trusted reference data and hardware-backed attestation must be validated outside the potentially compromised Android environment.