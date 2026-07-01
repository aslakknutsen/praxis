// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Signature, expiry, and key id extraction from query or path placement.

use http::Uri;

use super::config::{Encoding, Placement};

/// Values extracted from a signed URL.
pub(super) struct ExtractedSignature<'a> {
    pub signature: &'a str,
    pub expires: Option<&'a str>,
    pub key_id: Option<&'a str>,
    /// Raw resource path suffix for path placement (may be percent-encoded).
    pub resource_path_raw: Option<&'a str>,
}

/// Extract signing parameters from the request URI.
pub(super) fn extract_from_request<'a>(
    uri: &'a Uri,
    placement: Placement,
    path_prefix: Option<&str>,
    signature_param: &str,
    expires_param: &str,
    key_id_param: Option<&str>,
    encoding: Encoding,
) -> Option<ExtractedSignature<'a>> {
    match placement {
        Placement::Query => extract_query(
            uri,
            signature_param,
            expires_param,
            key_id_param,
        ),
        Placement::Path => extract_path(uri.path(), path_prefix?, encoding),
    }
}

fn extract_query<'a>(
    uri: &'a Uri,
    signature_param: &str,
    expires_param: &str,
    key_id_param: Option<&str>,
) -> Option<ExtractedSignature<'a>> {
    let qs = uri.query()?;
    let mut signature = None;
    let mut expires = None;
    let mut key_id = None;

    for pair in qs.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = match pair.split_once('=') {
            Some((k, v)) => (k, Some(v)),
            None => (pair, None),
        };
        if key == signature_param {
            signature = value;
        } else if key == expires_param {
            expires = value;
        } else if key_id_param.is_some_and(|kid| key == kid) {
            key_id = value;
        }
    }

    let signature = signature?;

    Some(ExtractedSignature {
        signature,
        expires,
        key_id,
        resource_path_raw: None,
    })
}

fn extract_path<'a>(
    path: &'a str,
    path_prefix: &str,
    encoding: Encoding,
) -> Option<ExtractedSignature<'a>> {
    if !path.starts_with(path_prefix) {
        return None;
    }

    let after_prefix = &path[path_prefix.len()..];
    if !after_prefix.starts_with('/') {
        return None;
    }

    let segments: Vec<&str> = after_prefix.split('/').filter(|s| !s.is_empty()).collect();
    if segments.len() < 2 {
        return None;
    }

    let expires_str = segments[0];
    if !is_valid_expires(expires_str) {
        return None;
    }

    let signature = segments[1];
    if !is_valid_signature(signature, encoding) {
        return None;
    }

    let resource_path_raw = if segments.len() == 2 {
        "/"
    } else {
        // Reconstruct from raw path bytes to preserve encoding until sanitize step.
        let suffix_start = path_prefix.len() + 1 + expires_str.len() + 1 + signature.len();
        if suffix_start >= path.len() {
            "/"
        } else {
            &path[suffix_start..]
        }
    };

    Some(ExtractedSignature {
        signature,
        expires: Some(expires_str),
        key_id: None,
        resource_path_raw: Some(resource_path_raw),
    })
}

fn is_valid_expires(s: &str) -> bool {
    !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit())
}

fn is_valid_signature(s: &str, encoding: Encoding) -> bool {
    match encoding {
        Encoding::Hex => !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit()),
        Encoding::Base64Url => {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        },
    }
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
    use crate::builtins::http::security::url_sign::config::Encoding;

    #[test]
    fn path_mode_extracts_resource_suffix() {
        let uri: Uri = "/s/1719859200/abc123/files/report.pdf".parse().unwrap();
        let extracted = extract_path(uri.path(), "/s", Encoding::Hex).unwrap();
        assert_eq!(extracted.signature, "abc123");
        assert_eq!(extracted.expires, Some("1719859200"));
        assert_eq!(extracted.resource_path_raw, Some("/files/report.pdf"));
    }

    #[test]
    fn path_mode_rejects_malformed_layout() {
        let uri: Uri = "/s/not-a-number/abc".parse().unwrap();
        assert!(extract_path(uri.path(), "/s", Encoding::Hex).is_none());
    }

    #[test]
    fn query_mode_extracts_params() {
        let uri: Uri = "/file?expires=99&sig=deadbeef&kid=v1".parse().unwrap();
        let extracted = extract_query(&uri, "sig", "expires", Some("kid")).unwrap();
        assert_eq!(extracted.signature, "deadbeef");
        assert_eq!(extracted.expires, Some("99"));
        assert_eq!(extracted.key_id, Some("v1"));
    }
}
