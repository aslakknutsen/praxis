// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Shared errors and limits for JSON body rewriting.

/// Maximum object/array nesting while rewriting.
pub(crate) const MAX_JSON_DEPTH: u32 = 128;

/// Why a rewrite failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RewriteError {
    /// Input is not a single JSON value.
    InvalidJson,
    /// Nesting exceeded [`MAX_JSON_DEPTH`].
    Depth,
}

impl RewriteError {
    /// Human-readable reason for logs and `on_invalid: error`.
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::InvalidJson => "invalid JSON",
            Self::Depth => "JSON nesting exceeds maximum depth",
        }
    }
}
