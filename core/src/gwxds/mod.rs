// SPDX-License-Identifier: MIT

//! Gateway xDS (gwxds) support.
//!
//! This module contains the proto-generated configuration types from
//! `gwxds.proto` and the translator that converts them into a praxis [`Config`].
//!
//! [`Config`]: crate::config::Config

mod proto;
mod translate;

pub use proto::{
    Backend, BackendRef, BackendTls, FailureMode, InferencePool, Listener, Protocol, Resource,
    Route, RouteMatch, TlsConfig,
};
pub use translate::translate;
