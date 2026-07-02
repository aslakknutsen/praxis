// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Canonical message construction for signed URL verification.

use http::Uri;

use super::config::{MessagePart, SignedUrlConfig, UriSource};

// -----------------------------------------------------------------------------
// Canonical Message
// -----------------------------------------------------------------------------

/// Build the canonical signed URL message bytes from config and request data.
#[must_use]
pub(crate) fn build_signed_url_message(
    cfg: &SignedUrlConfig,
    uri: &Uri,
    rewritten_path: Option<&str>,
    timestamp: Option<u64>,
    expiry: Option<u64>,
) -> Vec<u8> {
    let path = resolve_path(cfg.uri_source, uri, rewritten_path);
    let mut parts = Vec::with_capacity(cfg.message.parts.len());

    for part in &cfg.message.parts {
        match part {
            MessagePart::Path => parts.push(path.clone()),
            MessagePart::Timestamp => {
                if let Some(ts) = timestamp {
                    parts.push(ts.to_string());
                }
            },
            MessagePart::Expiry => {
                if let Some(exp) = expiry {
                    parts.push(exp.to_string());
                }
            },
        }
    }

    parts.join(&cfg.message.separator).into_bytes()
}

fn resolve_path(source: UriSource, uri: &Uri, rewritten_path: Option<&str>) -> String {
    match source {
        UriSource::Client => uri.path().to_owned(),
        UriSource::Rewritten => rewritten_path
            .map(|p| split_path_query(p).0.to_owned())
            .unwrap_or_else(|| uri.path().to_owned()),
    }
}

/// Split a rewritten path into path and optional query components.
pub(crate) fn split_path_query(path_and_query: &str) -> (&str, Option<&str>) {
    match path_and_query.split_once('?') {
        Some((path, query)) if !query.is_empty() => (path, Some(query)),
        Some((path, _)) => (path, None),
        None => (path_and_query, None),
    }
}
