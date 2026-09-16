// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Pipeline-level JSON extract pre-pass.
//!
//! At build time the pipeline scans consecutive [`BodyAccess::ReadOnly`]
//! filters for [`JsonExtractDecl`] declarations and compiles them into
//! a single [`JsonOps`] extract-only walk. At request time, when the
//! full request body is available (`end_of_stream`), the pre-pass runs
//! once before any filter's [`on_request_body`], writing results into
//! metadata and headers via [`JsonOpStore`].
//!
//! [`BodyAccess::ReadOnly`]: crate::body::BodyAccess::ReadOnly
//! [`JsonExtractDecl`]: crate::filter::JsonExtractDecl
//! [`on_request_body`]: crate::HttpFilter::on_request_body
//! [`JsonOpStore`]: crate::json_ops::JsonOpStore

use crate::filter::JsonExtractDecl;
use crate::json_ops::{JsonError, JsonOps};
use crate::json_ops::JsonOpStore;

/// Compiled extract-only pre-pass for one pipeline.
///
/// Built once at pipeline construction; applied per request at body EOS.
#[derive(Clone, Debug)]
pub(crate) struct JsonExtractPrePass {
    /// Compiled extract-only op set applied once per request body.
    ops: JsonOps,
}

impl JsonExtractPrePass {
    /// Compile declarations into a single extract-only [`JsonOps`] set.
    ///
    /// Returns `None` if `declarations` is empty (nothing to extract).
    ///
    /// # Errors
    ///
    /// Returns [`JsonError::Compile`] for invalid pointers, empty
    /// destination keys, or duplicate extract pointers.
    pub(crate) fn compile(declarations: Vec<JsonExtractDecl>) -> Result<Option<Self>, JsonError> {
        if declarations.is_empty() {
            return Ok(None);
        }
        let mut builder = JsonOps::builder();
        for decl in declarations {
            builder = builder.extract(&decl.pointer, decl.dest)?;
        }
        let ops = builder.build()?;
        Ok(Some(Self { ops }))
    }

    /// Run the extract pass over `body`, writing results into `store`.
    ///
    /// # Errors
    ///
    /// Returns [`JsonError::InvalidJson`] or [`JsonError::Depth`] when
    /// the body cannot be walked.
    pub(crate) fn apply(&self, body: &[u8], store: &mut dyn JsonOpStore) -> Result<(), JsonError> {
        self.ops.apply(body, Some(store))?;
        Ok(())
    }
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use super::*;
    use crate::json_ops::{ExtractDest, MapStore};

    #[test]
    fn empty_declarations_returns_none() {
        let result = JsonExtractPrePass::compile(vec![]).unwrap();
        assert!(result.is_none(), "no declarations means no pre-pass");
    }

    #[test]
    fn single_extract_populates_metadata() {
        let prepass = JsonExtractPrePass::compile(vec![JsonExtractDecl {
            pointer: "/model".to_owned(),
            dest: ExtractDest::metadata("req.model"),
        }])
        .unwrap()
        .expect("should produce a pre-pass");

        let body = br#"{"model":"gpt-4","stream":true}"#;
        let mut store = MapStore::new();
        prepass.apply(body, &mut store).unwrap();

        assert_eq!(store.metadata().get("req.model").map(String::as_str), Some("gpt-4"));
    }

    #[test]
    fn multiple_extracts_single_pass() {
        let prepass = JsonExtractPrePass::compile(vec![
            JsonExtractDecl {
                pointer: "/model".to_owned(),
                dest: ExtractDest::metadata("req.model"),
            },
            JsonExtractDecl {
                pointer: "/stream".to_owned(),
                dest: ExtractDest::metadata("req.stream"),
            },
        ])
        .unwrap()
        .expect("should produce a pre-pass");

        let body = br#"{"model":"gpt-4","stream":true}"#;
        let mut store = MapStore::new();
        prepass.apply(body, &mut store).unwrap();

        assert_eq!(store.metadata().get("req.model").map(String::as_str), Some("gpt-4"));
        assert_eq!(store.metadata().get("req.stream").map(String::as_str), Some("true"));
    }

    #[test]
    fn extract_to_header() {
        let prepass = JsonExtractPrePass::compile(vec![JsonExtractDecl {
            pointer: "/model".to_owned(),
            dest: ExtractDest::header("x-model"),
        }])
        .unwrap()
        .expect("should produce a pre-pass");

        let body = br#"{"model":"gpt-4"}"#;
        let mut store = MapStore::new();
        prepass.apply(body, &mut store).unwrap();

        assert_eq!(store.request_headers(), &[("x-model".to_owned(), "gpt-4".to_owned())]);
    }

    #[test]
    fn invalid_json_returns_error() {
        let prepass = JsonExtractPrePass::compile(vec![JsonExtractDecl {
            pointer: "/model".to_owned(),
            dest: ExtractDest::metadata("req.model"),
        }])
        .unwrap()
        .expect("should produce a pre-pass");

        let result = prepass.apply(b"not json", &mut MapStore::new());
        assert!(result.is_err(), "should fail on invalid JSON");
    }

    #[test]
    fn duplicate_pointer_rejected() {
        let result = JsonExtractPrePass::compile(vec![
            JsonExtractDecl {
                pointer: "/model".to_owned(),
                dest: ExtractDest::metadata("a"),
            },
            JsonExtractDecl {
                pointer: "/model".to_owned(),
                dest: ExtractDest::metadata("b"),
            },
        ]);
        assert!(result.is_err(), "duplicate extract pointers should fail compilation");
    }

    #[test]
    fn missing_pointer_does_not_fail() {
        let prepass = JsonExtractPrePass::compile(vec![JsonExtractDecl {
            pointer: "/nonexistent".to_owned(),
            dest: ExtractDest::metadata("nope"),
        }])
        .unwrap()
        .expect("should produce a pre-pass");

        let body = br#"{"model":"gpt-4"}"#;
        let mut store = MapStore::new();
        prepass.apply(body, &mut store).unwrap();

        assert!(
            store.metadata().get("nope").is_none(),
            "missing pointer should not write metadata"
        );
    }
}
