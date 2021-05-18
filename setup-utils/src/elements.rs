use crate::{BatchDeserializer, Error};
use algebra::{
    batch_verify_in_subgroup, cfg_iter, AffineCurve, CanonicalDeserialize, CanonicalSerialize, FpParameters,
    PrimeField, Read, SerializationError, Write, Zero,
};

#[cfg(not(feature = "wasm"))]
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use std::fmt;

/// Determines if point compression should be used.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum UseCompression {
    Yes,
    No,
}

impl fmt::Display for UseCompression {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            UseCompression::Yes => write!(f, "Yes"),
            UseCompression::No => write!(f, "No"),
        }
    }
}

/// Determines if points should be checked to be infinity.
#[derive(Copy, Clone, PartialEq)]
pub enum CheckForCorrectness {
    Full,
    OnlyNonZero,
    OnlyInGroup,
    No,
}

impl fmt::Display for CheckForCorrectness {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CheckForCorrectness::Full => write!(f, "Full"),
            CheckForCorrectness::OnlyNonZero => write!(f, "OnlyNonZero"),
            CheckForCorrectness::OnlyInGroup => write!(f, "OnlyInGroup"),
            CheckForCorrectness::No => write!(f, "No"),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ElementType {
    TauG1,
    TauG2,
    AlphaG1,
    BetaG1,
    BetaG2,
}

impl fmt::Display for ElementType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ElementType::TauG1 => write!(f, "TauG1"),
            ElementType::TauG2 => write!(f, "TauG2"),
            ElementType::AlphaG1 => write!(f, "AlphaG1"),
            ElementType::BetaG1 => write!(f, "BetaG1"),
            ElementType::BetaG2 => write!(f, "BetaG2"),
        }
    }
}

/// Determines which batch exponentiation algorithm to use
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum BatchExpMode {
    Auto,
    Direct,
    BatchInversion,
}

impl fmt::Display for BatchExpMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BatchExpMode::Auto => write!(f, "Auto"),
            BatchExpMode::Direct => write!(f, "Direct"),
            BatchExpMode::BatchInversion => write!(f, "Batch inversion"),
        }
    }
}

/// Determines which batch exponentiation algorithm to use
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum SubgroupCheckMode {
    Auto,
    Direct,
    Batched,
}

impl fmt::Display for SubgroupCheckMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SubgroupCheckMode::Auto => write!(f, "Auto"),
            SubgroupCheckMode::Direct => write!(f, "Direct"),
            SubgroupCheckMode::Batched => write!(f, "Batched"),
        }
    }
}

pub fn deserialize<T: CanonicalDeserialize, R: Read>(
    reader: R,
    compressed: UseCompression,
    check_correctness: CheckForCorrectness,
) -> core::result::Result<T, SerializationError> {
    match (compressed, check_correctness) {
        (UseCompression::No, CheckForCorrectness::No) => {
            CanonicalDeserialize::deserialize_uncompressed_unchecked(reader)
        }
        (UseCompression::Yes, CheckForCorrectness::No) => CanonicalDeserialize::deserialize_unchecked(reader),
        (UseCompression::No, CheckForCorrectness::Full) => CanonicalDeserialize::deserialize_uncompressed(reader),
        (UseCompression::Yes, CheckForCorrectness::Full) => CanonicalDeserialize::deserialize(reader),
        (..) => Err(SerializationError::InvalidData),
    }
}

pub fn serialize<T: CanonicalSerialize, W: Write>(
    element: &T,
    writer: W,
    compressed: UseCompression,
) -> core::result::Result<(), SerializationError> {
    match compressed {
        UseCompression::No => CanonicalSerialize::serialize_uncompressed(element, writer),
        UseCompression::Yes => CanonicalSerialize::serialize(element, writer),
    }
}

pub fn check_subgroup<C: AffineCurve>(
    elements: &[C],
    subgroup_check_mode: SubgroupCheckMode,
) -> core::result::Result<(), Error> {
    const SECURITY_PARAM: usize = 128;
    const BATCH_SIZE: usize = 1 << 12;
    let all_in_prime_order_subgroup = match (elements.len() > BATCH_SIZE, subgroup_check_mode) {
        (true, SubgroupCheckMode::Auto) | (_, SubgroupCheckMode::Batched) => {
            match batch_verify_in_subgroup(elements, SECURITY_PARAM, &mut rand::thread_rng()) {
                Ok(()) => true,
                _ => false,
            }
        }
        (false, SubgroupCheckMode::Auto) | (_, SubgroupCheckMode::Direct) => cfg_iter!(elements).all(|p| {
            p.mul(<<C::ScalarField as PrimeField>::Params as FpParameters>::MODULUS)
                .is_zero()
        }),
    };
    if !all_in_prime_order_subgroup {
        return Err(Error::IncorrectSubgroup);
    }

    Ok(())
}

pub fn read_vec<G: AffineCurve, R: Read>(
    mut reader: R,
    compressed: UseCompression,
    check_for_correctness: CheckForCorrectness,
) -> Result<Vec<G>, Error> {
    let size = match compressed {
        UseCompression::Yes => G::SERIALIZED_SIZE,
        UseCompression::No => G::UNCOMPRESSED_SIZE,
    };
    let length = u64::deserialize(&mut reader)? as usize;
    let mut bytes = vec![0u8; length * size];
    reader.read_exact(&mut bytes)?;
    bytes.read_batch(compressed, check_for_correctness)
}
