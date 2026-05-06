// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

#![deny(unsafe_code)]

//! Server bootstrap for the Praxis proxy.

pub mod gwxds;
pub(crate) mod pipelines;
pub mod preflight;
pub(crate) mod reload;
mod server;
pub(crate) mod watcher;

pub use praxis_core::{config::load_config, logging::init_tracing};
pub use server::{check_root_privilege, fatal, resolve_config_path, run_server, run_server_gwxds, run_server_with_registry};
