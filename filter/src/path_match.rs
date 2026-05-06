// SPDX-License-Identifier: MIT

//! Gateway API–aligned HTTP path matching helpers shared by the router and
//! request conditions.

/// Byte length of the path prefix for longest-prefix tie-breaking.
///
/// Trailing slashes on the configured prefix are ignored (`/api` ≡ `/api/`).
pub(crate) fn gateway_path_prefix_specificity(path_prefix: &str) -> usize {
    let p = path_prefix.trim_end_matches('/');
    if p.is_empty() {
        1
    } else {
        p.len()
    }
}

/// Gateway API–style path prefix match (segment / element-wise).
///
/// A prefix `/foo` matches `/foo`, `/foo/`, and `/foo/bar` but not `/foobar`.
/// Trailing slashes on the configured prefix are ignored (`/foo` ≡ `/foo/`).
pub(crate) fn gateway_path_prefix_matches(path: &str, path_prefix: &str) -> bool {
    let prefix = path_prefix.trim_end_matches('/');
    if prefix.is_empty() {
        return true;
    }
    if path == prefix {
        return true;
    }
    if !path.starts_with(prefix) {
        return false;
    }
    path.as_bytes().get(prefix.len()) == Some(&b'/')
}
