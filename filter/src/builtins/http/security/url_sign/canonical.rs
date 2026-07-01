// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Canonical signing input construction.

use std::collections::BTreeMap;

use http::{HeaderMap, Method, Uri};
use percent_encoding::{AsciiSet, CONTROLS};

use super::config::{CanonicalConfig, Placement};
use super::path::{percent_decode_path, sanitize_resource_path};

/// Characters percent-encoded in canonical query values.
const QUERY_VALUE_ENCODE_SET: &AsciiSet = &CONTROLS.add(b' ').add(b'"').add(b'#').add(b'&').add(b'+').add(b'=');

/// Inputs needed to build the canonical signing string.
pub(super) struct CanonicalInputs<'a> {
    pub method: &'a Method,
    pub uri: &'a Uri,
    pub headers: &'a HeaderMap,
    pub placement: Placement,
    pub canonical: &'a CanonicalConfig,
    pub signature_param: &'a str,
    pub expires_param: &'a str,
    pub key_id_param: Option<&'a str>,
    /// Expiry string from the URL (empty when absent and not required).
    pub expires: &'a str,
    /// Resource path for path placement (already extracted, may be encoded).
    pub resource_path_raw: Option<&'a str>,
}

/// Build the canonical signing input per the URL signing spec.
///
/// Format (lines separated by `\n`, no trailing newline):
/// `{METHOD}\n{PATH}\n{QUERY}\n{EXPIRES}\n{HOST}`
pub(super) fn build_canonical_input(inputs: &CanonicalInputs<'_>) -> Result<String, ()> {
    let method = if inputs.canonical.include_method {
        inputs.method.as_str().to_ascii_uppercase()
    } else {
        String::new()
    };

    let path = canonical_path(inputs)?;

    let query = if inputs.canonical.include_query {
        canonical_query(
            inputs.uri,
            inputs.signature_param,
            inputs.expires_param,
            inputs.key_id_param,
        )
    } else {
        String::new()
    };

    let expires = inputs.expires.to_owned();

    let host = if inputs.canonical.include_host {
        host_without_port(inputs.headers)
    } else {
        String::new()
    };

    Ok(format!("{method}\n{path}\n{query}\n{expires}\n{host}"))
}

fn canonical_path(inputs: &CanonicalInputs<'_>) -> Result<String, ()> {
    match inputs.placement {
        Placement::Query => percent_decode_path(inputs.uri.path()),
        Placement::Path => {
            let raw = inputs.resource_path_raw.ok_or(())?;
            sanitize_resource_path(raw)
        },
    }
}

/// Build RFC 3986-style canonical query: sorted pairs, sig params excluded.
fn canonical_query(
    uri: &Uri,
    signature_param: &str,
    expires_param: &str,
    key_id_param: Option<&str>,
) -> String {
    let Some(qs) = uri.query() else {
        return String::new();
    };

    let mut pairs: BTreeMap<(String, String), ()> = BTreeMap::new();

    for pair in qs.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        if key == signature_param || key == expires_param {
            continue;
        }
        if key_id_param.is_some_and(|kid| key == kid) {
            continue;
        }
        pairs.insert((key.to_owned(), value.to_owned()), ());
    }

    let mut out = String::new();
    for ((key, value), ()) in pairs {
        if !out.is_empty() {
            out.push('&');
        }
        out.push_str(&key);
        out.push('=');
        out.push_str(&percent_encode_query_value(&value));
    }
    out
}

fn percent_encode_query_value(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, QUERY_VALUE_ENCODE_SET).to_string()
}

fn host_without_port(headers: &HeaderMap) -> String {
    let Some(host) = headers.get("host").and_then(|v| v.to_str().ok()) else {
        return String::new();
    };

    if let Some(bracket_end) = host.find(']') {
        return host[..=bracket_end].to_ascii_lowercase();
    }

    host.split(':')
        .next()
        .unwrap_or(host)
        .to_ascii_lowercase()
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
    use http::{HeaderMap, Method, Uri};

    use super::*;
    use crate::builtins::http::security::url_sign::config::{CanonicalConfig, Placement};

    #[test]
    fn query_mode_worked_example() {
        let uri: Uri = "/files/report.pdf?token=abc&expires=1719859200&sig=deadbeef"
            .parse()
            .unwrap();
        let headers = HeaderMap::new();
        let canonical = CanonicalConfig::default();

        let inputs = CanonicalInputs {
            method: &Method::GET,
            uri: &uri,
            headers: &headers,
            placement: Placement::Query,
            canonical: &canonical,
            signature_param: "sig",
            expires_param: "expires",
            key_id_param: None,
            expires: "1719859200",
            resource_path_raw: None,
        };

        let result = build_canonical_input(&inputs).unwrap();
        assert_eq!(
            result,
            "GET\n/files/report.pdf\ntoken=abc\n1719859200\n"
        );
    }

    #[test]
    fn excludes_signature_and_kid_params() {
        let uri: Uri = "/x?a=1&kid=v1&sig=abc&expires=99".parse().unwrap();
        let headers = HeaderMap::new();
        let canonical = CanonicalConfig::default();

        let inputs = CanonicalInputs {
            method: &Method::GET,
            uri: &uri,
            headers: &headers,
            placement: Placement::Query,
            canonical: &canonical,
            signature_param: "sig",
            expires_param: "expires",
            key_id_param: Some("kid"),
            expires: "99",
            resource_path_raw: None,
        };

        let result = build_canonical_input(&inputs).unwrap();
        assert_eq!(result, "GET\n/x\na=1\n99\n");
    }

    #[test]
    fn include_host_lowercases_and_strips_port() {
        let uri: Uri = "/".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("host", "Example.COM:8080".parse().unwrap());
        let mut canonical = CanonicalConfig::default();
        canonical.include_host = true;

        let inputs = CanonicalInputs {
            method: &Method::GET,
            uri: &uri,
            headers: &headers,
            placement: Placement::Query,
            canonical: &canonical,
            signature_param: "sig",
            expires_param: "expires",
            key_id_param: None,
            expires: "1",
            resource_path_raw: None,
        };

        let result = build_canonical_input(&inputs).unwrap();
        assert_eq!(result, "GET\n/\n\n1\nexample.com");
    }
}
