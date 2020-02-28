//! # SNARK MPC Utils
//!
//! Utilities for building MPC Ceremonies for large SNARKs with Zexe.
//! Provides traits for batched writing and reading Group Elements
//! to buffers.
pub mod errors;
pub use errors::{Error, VerificationError};

mod elements;
pub use elements::{ElementType, UseCompression};

mod helpers;
pub use helpers::*;

mod io;
pub use io::{buffer_size, BatchDeserializer, Deserializer, ParBatchDeserializer, Serializer};
