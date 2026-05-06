// SPDX-License-Identifier: MIT
#![deny(unsafe_code)]
#![deny(unreachable_pub)]

//! ADS gRPC client for consuming istiod's gwxds xDS stream.
//!
//! # Usage
//!
//! ```no_run
//! use tokio::sync::mpsc;
//! use praxis_xds_client::client::run;
//!
//! #[tokio::main]
//! async fn main() {
//!     let (tx, mut rx) = mpsc::channel(8);
//!     tokio::spawn(run("http://istiod:15010".to_owned(), tx));
//!     while let Some(resources) = rx.recv().await {
//!         println!("received {} gwxds resources", resources.len());
//!     }
//! }
//! ```

mod ads;
mod client;
mod node;
mod proto;

pub use ads::XdsError;
pub use client::{GW_TYPE_URL, run};
