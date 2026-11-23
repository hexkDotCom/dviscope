//! DVIScope wire contracts.
//!
//! Everything a client and the server must agree on byte for byte: identifiers, canonical
//! JSON and digests, the wire types of the ingest and evidence schemas, limits and error
//! codes. No I/O, no clock, no randomness except where an ID generator is passed in.
//!
//! The wire types are **provisional** until the 0.1 contracts are frozen: they carry development
//! schema versions (`dviscope.ingest/1.0-dev.N`), see [`schema`].

#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod canonical;
pub mod errors;
pub mod ids;
pub mod limits;
pub mod schema;
pub mod values;
pub mod wire;

pub use canonical::{CanonicalError, Digest, canonical_json, digest_of};
pub use errors::ErrorCode;
