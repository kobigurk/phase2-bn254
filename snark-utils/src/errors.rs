use std::io;
use thiserror::Error;
use zexe_algebra::SerializationError;

use crate::ElementType;

/// Errors that might occur during deserialization.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Disk IO error: {0}")]
    IoError(#[from] io::Error),
    #[error("Serialization error in Zexe: {0}")]
    ZexeSerializationError(#[from] SerializationError),
    #[error("Got point at infinity")]
    PointAtInfinity,
    #[error("Index of {0} must not exceed {1} (got {2}.")]
    PositionError(ElementType, usize, usize),
    #[error("Error during verification: {0}")]
    VerificationError(#[from] VerificationError),
    #[error("Invalid variable length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },
    #[error("Chunk does not have a min and max")]
    InvalidChunk,
}

// todo: make this more detailed so that we can know which
// exact pairing ratio check failed
#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("Invalid ratio! Context: {0}")]
    /// The ratio check via the pairing of the provided elements failed
    InvalidRatio(&'static str),
    #[error("Invalid generator for {0} powers")]
    /// The first power of Tau was not the generator of that group
    InvalidGenerator(ElementType),
}
