# praxis-json-string-scan

Fused SIMD scan for JSON string terminators: `"`, `\`, and unescaped
control bytes (`0x00..=0x1F`).

## Provenance

`find_special.rs` and `simd.rs` are derived from [nosj](https://github.com/yaroslav/nosj)
v0.2.0 (`src/scalars.rs`, `src/scan.rs`), Copyright (c) 2026 Yaroslav Markin,
MIT License. Stripped to the `MODE_STANDARD` predicate only.

This is the only workspace crate that permits `unsafe` (SIMD intrinsics).
