// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Path decoding and sanitization for URL signing.

use percent_encoding::percent_decode_str;

use crate::builtins::http::transformation::path_sanitize::normalize_rewritten_path;

/// Percent-decode a URI path and ensure it starts with `/`.
pub(super) fn percent_decode_path(path: &str) -> Result<String, ()> {
    let decoded = percent_decode_str(path)
        .decode_utf8()
        .map_err(|_| ())?;
    let decoded = decoded.as_ref();
    if decoded.starts_with('/') {
        Ok(decoded.to_owned())
    } else {
        Ok(format!("/{decoded}"))
    }
}

/// Decode, reject traversal, normalize, and reject semantic changes.
pub(super) fn sanitize_resource_path(raw: &str) -> Result<String, ()> {
    let decoded = percent_decode_path(raw)?;

    for segment in decoded.split('/') {
        if segment == ".." {
            return Err(());
        }
    }

    let normalized = normalize_rewritten_path(&decoded);
    if normalized.as_ref() != decoded {
        return Err(());
    }

    Ok(normalized.into_owned())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn rejects_encoded_dot_dot() {
        assert!(sanitize_resource_path("/public/%2e%2e/admin").is_err());
    }

    #[test]
    fn rejects_encoded_double_slash() {
        assert!(sanitize_resource_path("/a%2f%2fb").is_err());
    }

    #[test]
    fn accepts_clean_path() {
        assert_eq!(
            sanitize_resource_path("/files/report.pdf").unwrap(),
            "/files/report.pdf"
        );
    }

    #[test]
    fn rejects_double_slash() {
        assert!(sanitize_resource_path("/a//b").is_err());
    }
}
