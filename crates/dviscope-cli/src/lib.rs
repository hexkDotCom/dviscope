//! DVIScope CLI library (the `dviscope` binary is a thin wrapper).
//!
//! Configuration, the HTTPS client with origin rules, TLS set-up, diagnostics, log
//! extraction, rule checks, the delivery journal and the verdict gate.

pub mod activation;
pub mod client;
pub mod collect;
pub mod config;
pub mod crash;
pub mod doctor;
pub mod import;
pub mod journal;
pub mod platform;
pub mod reconcile;
pub mod rules;
pub mod run;
pub mod source;
pub mod spool;
pub mod tls;
pub mod transport;
pub mod verdict;
