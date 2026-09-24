// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Wildcard-aware SNI matching, shared by certificate selection and SNI
//! routing.
//!
//! A single [`SniMatcher`] resolves an SNI hostname to an associated value —
//! a certificate for cert selection, an upstream address for routing. The two
//! callers answer to different authorities, so the wildcard semantics are
//! chosen per caller through the [`WildcardMatch`] policy rather than baked in:
//!
//! - [`WildcardMatch::SingleLabel`] — certificate identity (RFC 6125, superseded by [RFC 9525]). A wildcard matches
//!   exactly one leftmost label, and a pattern must have at least three labels (`*.com` is rejected).
//! - [`WildcardMatch::Suffix`] — routing convenience with no governing RFC. A wildcard matches any number of leading
//!   labels, longest suffix winning, and `*.com` is permitted.
//!
//! Exact matches always win over wildcards. Matching is case-insensitive
//! ([RFC 4343]); a single trailing dot on the looked-up hostname is ignored.
//!
//! [RFC 9525]: https://datatracker.ietf.org/doc/html/rfc9525
//! [RFC 4343]: https://datatracker.ietf.org/doc/html/rfc4343

use std::{borrow::Cow, cmp::Reverse, collections::HashMap};

use crate::sni_name::{self, SniNameError};

// -----------------------------------------------------------------------------
// WildcardMatch
// -----------------------------------------------------------------------------

/// How a wildcard SNI pattern matches a hostname.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WildcardMatch {
    /// A wildcard matches exactly one leftmost label (RFC 6125 / RFC 9525
    /// certificate-identity semantics): `*.example.com` matches
    /// `app.example.com` but not `a.b.example.com`. Patterns must have at
    /// least three labels, so `*.com` is rejected at build.
    SingleLabel,

    /// A wildcard matches any number of leading labels, longest configured
    /// suffix winning: `*.example.com` also matches `a.b.example.com`. A
    /// routing convenience with no governing RFC; `*.com` is permitted.
    Suffix,
}

// -----------------------------------------------------------------------------
// SniMatcherError
// -----------------------------------------------------------------------------

/// Why building an [`SniMatcher`] failed.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SniMatcherError {
    /// A configured pattern is not a valid SNI server name under the policy.
    #[error("server name '{pattern}': {source}")]
    InvalidPattern {
        /// The offending pattern, as written.
        pattern: String,

        /// Why the pattern is invalid.
        #[source]
        source: SniNameError,
    },

    /// The same pattern was configured more than once.
    #[error("duplicate server name '{pattern}'")]
    DuplicatePattern {
        /// The duplicated pattern, as written (e.g. `*.example.com`).
        pattern: String,
    },
}

// -----------------------------------------------------------------------------
// Pattern validation
// -----------------------------------------------------------------------------

/// Validate an SNI pattern under a wildcard match policy.
///
/// Runs the shared [`sni_name::validate`] rules, then the policy-specific rule:
/// under [`WildcardMatch::SingleLabel`] a wildcard must cover a subdomain (at
/// least three labels), so `*.com` yields [`SniNameError::WildcardTooShallow`].
/// [`WildcardMatch::Suffix`] adds no extra rule.
///
/// This is the single source of truth for the `>= 3` label rule; both
/// [`SniMatcher::build`] and cert-config validation call it.
///
/// # Errors
///
/// Returns [`SniNameError`] when the pattern is malformed for the policy.
pub fn validate_pattern(pattern: &str, policy: WildcardMatch) -> Result<(), SniNameError> {
    sni_name::validate(pattern)?;

    if policy == WildcardMatch::SingleLabel && pattern.starts_with("*.") && pattern.split('.').count() < 3 {
        return Err(SniNameError::WildcardTooShallow);
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// SniMatcher
// -----------------------------------------------------------------------------

/// Resolves an SNI hostname to an associated value under a [`WildcardMatch`]
/// policy.
///
/// Build once from `(pattern, value)` entries, then [`lookup`](Self::lookup)
/// per connection. Exact matches win over wildcards.
pub struct SniMatcher<V> {
    /// Exact hostname (lowercased) to value.
    exact: HashMap<String, V>,

    /// Wildcard index; shape depends on the policy.
    wildcard: Wildcard<V>,
}

/// Wildcard index, keyed by the policy chosen at build time.
enum Wildcard<V> {
    /// Suffix after `*.` (no leading dot) to value; probed by single label.
    SingleLabel(HashMap<String, V>),

    /// `(suffix incl. leading dot, value)`, sorted longest-first.
    Suffix(Vec<(String, V)>),
}

impl<V> SniMatcher<V> {
    /// Build a matcher from `(pattern, value)` entries under `policy`.
    ///
    /// Each pattern is validated (see [`validate_pattern`]) and indexed as an
    /// exact hostname or a wildcard. Patterns are compared case-insensitively.
    ///
    /// # Errors
    ///
    /// - [`SniMatcherError::InvalidPattern`] if a pattern is malformed for the policy.
    /// - [`SniMatcherError::DuplicatePattern`] if a pattern repeats (comparing case-insensitively).
    pub fn build<I>(entries: I, policy: WildcardMatch) -> Result<Self, SniMatcherError>
    where
        I: IntoIterator<Item = (String, V)>,
    {
        let mut builder = Builder::default();
        for (pattern, value) in entries {
            builder.insert(policy, pattern, value)?;
        }
        Ok(builder.finish(policy))
    }

    /// Resolve `sni` to its value, if any configured pattern matches.
    ///
    /// Exact matches win over wildcards. Case-insensitive; a single trailing
    /// dot on `sni` is ignored.
    pub fn lookup(&self, sni: &str) -> Option<&V> {
        let trimmed = sni.strip_suffix('.').unwrap_or(sni);
        // Real-world SNI is virtually always lowercase already; keys are
        // lowercased at build, so only a mixed-case name pays for a copy.
        let lower: Cow<'_, str> = if trimmed.bytes().any(|byte| byte.is_ascii_uppercase()) {
            Cow::Owned(trimmed.to_ascii_lowercase())
        } else {
            Cow::Borrowed(trimmed)
        };
        let name = lower.as_ref();

        if let Some(value) = self.exact.get(name) {
            return Some(value);
        }

        match &self.wildcard {
            Wildcard::SingleLabel(map) => {
                // A wildcard matches exactly one dot-free label plus the stored
                // suffix, so splitting at the first dot yields the unique
                // candidate key. The empty-label guard preserves the length
                // check (`.example.com` must not match `*.example.com`).
                let (label, rest) = name.split_once('.')?;
                if label.is_empty() {
                    return None;
                }
                map.get(rest)
            },
            Wildcard::Suffix(list) => list
                .iter()
                .find(|(stored, _)| name.len() > stored.len() && name.ends_with(stored.as_str()))
                .map(|(_, value)| value),
        }
    }

    /// Configured exact hostnames (lowercased). For diagnostics and tests.
    pub fn exact_names(&self) -> impl Iterator<Item = &str> {
        self.exact.keys().map(String::as_str)
    }

    /// Configured wildcard patterns, rendered as written (e.g. `*.example.com`).
    /// For diagnostics and tests.
    pub fn wildcard_patterns(&self) -> Vec<String> {
        match &self.wildcard {
            Wildcard::SingleLabel(map) => map.keys().map(|suffix| format!("*.{suffix}")).collect(),
            Wildcard::Suffix(list) => list.iter().map(|(suffix, _)| format!("*{suffix}")).collect(),
        }
    }
}

/// Accumulates validated, indexed entries while [`SniMatcher::build`] runs.
///
/// Split out so `build` stays small and each `insert` takes few arguments.
struct Builder<V> {
    /// Exact hostname (lowercased) to value.
    exact: HashMap<String, V>,

    /// Single-label wildcard suffixes (no leading dot) to value.
    single: HashMap<String, V>,

    /// Suffix wildcard `(suffix incl. leading dot, value)` pairs.
    suffix: Vec<(String, V)>,
}

impl<V> Default for Builder<V> {
    fn default() -> Self {
        Self {
            exact: HashMap::new(),
            single: HashMap::new(),
            suffix: Vec::new(),
        }
    }
}

impl<V> Builder<V> {
    /// Validate one `(pattern, value)` entry and index it by policy.
    fn insert(&mut self, policy: WildcardMatch, pattern: String, value: V) -> Result<(), SniMatcherError> {
        validate_pattern(&pattern, policy).map_err(|source| SniMatcherError::InvalidPattern {
            pattern: pattern.clone(),
            source,
        })?;

        let lower = pattern.to_ascii_lowercase();

        let Some(rest) = lower.strip_prefix("*.") else {
            return if self.exact.insert(lower, value).is_some() {
                Err(SniMatcherError::DuplicatePattern { pattern })
            } else {
                Ok(())
            };
        };

        match policy {
            WildcardMatch::SingleLabel => {
                if self.single.insert(rest.to_owned(), value).is_some() {
                    return Err(SniMatcherError::DuplicatePattern { pattern });
                }
            },
            WildcardMatch::Suffix => {
                // The stored suffix keeps its leading dot: ".example.com".
                let dotted = format!(".{rest}");
                if self.suffix.iter().any(|(stored, _)| stored == &dotted) {
                    return Err(SniMatcherError::DuplicatePattern { pattern });
                }
                self.suffix.push((dotted, value));
            },
        }

        Ok(())
    }

    /// Finalise the index for `policy` into an [`SniMatcher`].
    fn finish(mut self, policy: WildcardMatch) -> SniMatcher<V> {
        // Longest suffix wins, so probe longest-first.
        self.suffix.sort_by_key(|(stored, _)| Reverse(stored.len()));

        let wildcard = match policy {
            WildcardMatch::SingleLabel => Wildcard::SingleLabel(self.single),
            WildcardMatch::Suffix => Wildcard::Suffix(self.suffix),
        };

        SniMatcher {
            exact: self.exact,
            wildcard,
        }
    }
}

impl<V> std::fmt::Debug for SniMatcher<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniMatcher")
            .field("exact", &self.exact.keys().collect::<Vec<_>>())
            .field("wildcards", &self.wildcard_patterns())
            .finish()
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    /// Build a matcher over owned `String` values from `&str` pairs.
    fn make(entries: &[(&str, &str)], policy: WildcardMatch) -> SniMatcher<String> {
        let owned = entries
            .iter()
            .map(|(pattern, value)| ((*pattern).to_owned(), (*value).to_owned()));
        SniMatcher::build(owned, policy).expect("test matcher should build")
    }

    /// Look up `sni` and return the matched value as `&str`, if any.
    fn resolve<'matcher>(matcher: &'matcher SniMatcher<String>, sni: &str) -> Option<&'matcher str> {
        matcher.lookup(sni).map(String::as_str)
    }

    // --- exact matching (both policies) ---------------------------------------

    #[test]
    fn exact_match_wins() {
        for policy in [WildcardMatch::SingleLabel, WildcardMatch::Suffix] {
            let matcher = make(&[("api.example.com", "exact"), ("*.example.com", "wild")], policy);
            assert_eq!(resolve(&matcher, "api.example.com"), Some("exact"), "{policy:?}");
        }
    }

    #[test]
    fn case_insensitive_lookup() {
        for policy in [WildcardMatch::SingleLabel, WildcardMatch::Suffix] {
            let matcher = make(&[("API.Example.COM", "v")], policy);
            assert_eq!(resolve(&matcher, "api.example.com"), Some("v"), "{policy:?}");
            assert_eq!(resolve(&matcher, "API.EXAMPLE.COM"), Some("v"), "{policy:?}");
        }
    }

    #[test]
    fn trailing_dot_normalized() {
        for policy in [WildcardMatch::SingleLabel, WildcardMatch::Suffix] {
            let matcher = make(&[("api.example.com", "v")], policy);
            assert_eq!(resolve(&matcher, "api.example.com."), Some("v"), "{policy:?}");
        }
    }

    #[test]
    fn no_match_is_none() {
        for policy in [WildcardMatch::SingleLabel, WildcardMatch::Suffix] {
            let matcher = make(&[("api.example.com", "v")], policy);
            assert_eq!(resolve(&matcher, "other.example.com"), None, "{policy:?}");
        }
    }

    // --- SingleLabel policy ---------------------------------------------------

    #[test]
    fn single_label_matches_one_level() {
        let matcher = make(&[("*.example.com", "wild")], WildcardMatch::SingleLabel);
        assert_eq!(resolve(&matcher, "app.example.com"), Some("wild"));
    }

    #[test]
    fn single_label_rejects_multi_level() {
        let matcher = make(&[("*.example.com", "wild")], WildcardMatch::SingleLabel);
        assert_eq!(
            resolve(&matcher, "a.b.example.com"),
            None,
            "multi-level must not match SingleLabel"
        );
    }

    #[test]
    fn single_label_wildcard_does_not_match_bare_suffix() {
        let matcher = make(&[("*.example.com", "wild")], WildcardMatch::SingleLabel);
        assert_eq!(resolve(&matcher, "example.com"), None);
        assert_eq!(resolve(&matcher, ".example.com"), None, "empty label must not match");
    }

    #[test]
    fn single_label_rejects_two_label_pattern() {
        let err = SniMatcher::build(vec![("*.com".to_owned(), "v")], WildcardMatch::SingleLabel).unwrap_err();
        assert!(
            matches!(
                &err,
                SniMatcherError::InvalidPattern {
                    source: SniNameError::WildcardTooShallow,
                    ..
                }
            ),
            "got {err:?}"
        );
        assert!(err.to_string().contains("at least 3 labels"), "{err}");
    }

    // --- Suffix policy --------------------------------------------------------

    #[test]
    fn suffix_matches_multi_level() {
        let matcher = make(&[("*.example.com", "wild")], WildcardMatch::Suffix);
        assert_eq!(resolve(&matcher, "app.example.com"), Some("wild"));
        assert_eq!(
            resolve(&matcher, "a.b.example.com"),
            Some("wild"),
            "multi-level matches Suffix"
        );
    }

    #[test]
    fn suffix_longest_wins() {
        let matcher = make(
            &[("*.example.com", "short"), ("*.sub.example.com", "long")],
            WildcardMatch::Suffix,
        );
        assert_eq!(
            resolve(&matcher, "app.sub.example.com"),
            Some("long"),
            "longest suffix should win"
        );
    }

    #[test]
    fn suffix_does_not_match_bare_suffix() {
        let matcher = make(&[("*.example.com", "wild")], WildcardMatch::Suffix);
        assert_eq!(
            resolve(&matcher, "example.com"),
            None,
            "wildcard must not match the bare suffix"
        );
    }

    #[test]
    fn suffix_permits_two_label_pattern() {
        let matcher = make(&[("*.com", "wild")], WildcardMatch::Suffix);
        assert_eq!(resolve(&matcher, "a.com"), Some("wild"), "*.com is allowed for routing");
    }

    // --- build errors (both policies) -----------------------------------------

    #[test]
    fn duplicate_exact_rejected() {
        let err = SniMatcher::build(
            vec![("api.example.com".to_owned(), 1), ("API.example.com".to_owned(), 2)],
            WildcardMatch::Suffix,
        )
        .unwrap_err();
        assert!(matches!(err, SniMatcherError::DuplicatePattern { .. }), "got {err:?}");
    }

    #[test]
    fn duplicate_wildcard_rejected() {
        for policy in [WildcardMatch::SingleLabel, WildcardMatch::Suffix] {
            let err = SniMatcher::build(
                vec![("*.example.com".to_owned(), 1), ("*.example.com".to_owned(), 2)],
                policy,
            )
            .unwrap_err();
            assert!(
                matches!(err, SniMatcherError::DuplicatePattern { .. }),
                "{policy:?}: {err:?}"
            );
        }
    }

    #[test]
    fn invalid_pattern_rejected() {
        for policy in [WildcardMatch::SingleLabel, WildcardMatch::Suffix] {
            let err = SniMatcher::build(vec![("foo.*.com".to_owned(), 1)], policy).unwrap_err();
            assert!(
                matches!(
                    &err,
                    SniMatcherError::InvalidPattern {
                        source: SniNameError::InvalidWildcard,
                        ..
                    }
                ),
                "{policy:?}: {err:?}"
            );
        }
    }

    // --- diagnostics ----------------------------------------------------------

    #[test]
    fn reports_configured_patterns() {
        let matcher = make(
            &[("api.example.com", "a"), ("*.example.com", "b")],
            WildcardMatch::Suffix,
        );
        assert_eq!(matcher.exact_names().collect::<Vec<_>>(), vec!["api.example.com"]);
        assert_eq!(matcher.wildcard_patterns(), vec!["*.example.com".to_owned()]);
    }
}
