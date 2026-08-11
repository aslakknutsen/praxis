// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! External load generator tool wrappers.

/// Fortio HTTP/TCP load generator.
pub mod fortio;
/// Streaming passthrough client with TTFB measurement.
pub mod streaming;
/// Vegeta HTTP load generator (open-loop).
pub mod vegeta;
