//! Systemd credential management CLI.
//!
//! Wraps `systemd-creds` for creating, storing, rotating, and distributing
//! encrypted secrets via systemd's credential mechanism.
//!
//! ## Modules
//! - `cli` — Command-line handlers
//! - `core` — Business logic (audit, credstore, dropin, metadata)
//! - `models` — Data structures
//! - `util` — System utilities (fs, systemd)

pub mod cli;
pub mod constants;
pub mod core;
pub mod models;
pub mod util;
