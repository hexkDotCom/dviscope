//! DVIScope algorithms. Pure and deterministic: no file system, network, environment, clock
//! or randomness (checked by `xtask deps-check` and clippy's disallowed methods). Time,
//! IDs and policies are passed in.

#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod classify;
pub mod compare;
pub mod eligibility;
pub mod execution;
pub mod expectation;
pub mod extract;
pub mod feature;
pub mod health;
pub mod model_main;
pub mod outcome;
pub mod packs;
pub mod readiness;
pub mod rule_check;
pub mod settlement;
