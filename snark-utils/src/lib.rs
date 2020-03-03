//! # SNARK MPC Utils
//!
//! Utilities for building MPC Ceremonies for large SNARKs with Zexe.
//! Provides traits for batched writing and reading Group Elements
//! to buffers.
pub mod errors;
pub use errors::{Error, InvariantKind, Phase2Error, VerificationError};

mod groth16_utils;
pub use groth16_utils::Groth16Params;

mod elements;
pub use elements::{ElementType, UseCompression};

mod helpers;
pub use helpers::*;

mod io;
pub use io::{buffer_size, BatchDeserializer, Deserializer, ParBatchDeserializer, Serializer};

// Re-exports for handling hashes
pub use blake2::digest::generic_array::GenericArray;
pub use typenum::U64;
