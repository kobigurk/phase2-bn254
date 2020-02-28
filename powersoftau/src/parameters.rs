use std::fmt;
use std::io;
use std::marker::PhantomData;
use thiserror::Error;
use zexe_algebra::{CanonicalSerialize, PairingEngine, SerializationError, Zero};

/// The sizes of the group elements of a curve
#[derive(Clone, PartialEq, Eq, Default, Debug)]
pub struct CurveParams<E> {
    /// Size of a G1 Element
    pub g1: usize,
    /// Size of a G2 Element
    pub g2: usize,
    /// Size of a compressed G1 Element
    pub g1_compressed: usize,
    /// Size of a compressed G2 Element
    pub g2_compressed: usize,
    engine_type: PhantomData<E>,
}

impl<E: PairingEngine> CurveParams<E> {
    pub fn new() -> CurveParams<E> {
        let g1 = <E as PairingEngine>::G1Affine::zero();
        let mut g1_bytes_compressed = vec![0; <E as PairingEngine>::G1Affine::buffer_size()];
        g1.serialize(&[], &mut g1_bytes_compressed)
            .expect("could not serialize G1 element");
        let g1_compressed = g1_bytes_compressed.len();
        let g1_size = 2 * g1_compressed;

        let g2 = <E as PairingEngine>::G2Affine::zero();
        let mut g2_bytes_compressed = vec![0; <E as PairingEngine>::G2Affine::buffer_size()];
        g2.serialize(&[], &mut g2_bytes_compressed)
            .expect("could not serialize G2 element");
        let g2_compressed = g2_bytes_compressed.len();
        let g2_size = 2 * g2_compressed;

        CurveParams {
            g1: g1_size,
            g2: g2_size,
            g1_compressed,
            g2_compressed,
            engine_type: PhantomData,
        }
    }
}

impl<E> CurveParams<E> {
    pub fn g1_size(&self, compression: UseCompression) -> usize {
        match compression {
            UseCompression::Yes => self.g1_compressed,
            UseCompression::No => self.g1,
        }
    }

    pub fn g2_size(&self, compression: UseCompression) -> usize {
        match compression {
            UseCompression::Yes => self.g2_compressed,
            UseCompression::No => self.g2,
        }
    }

    pub fn get_size(&self, element_type: ElementType, compression: UseCompression) -> usize {
        match element_type {
            ElementType::AlphaG1 | ElementType::BetaG1 | ElementType::TauG1 => {
                self.g1_size(compression)
            }
            ElementType::BetaG2 | ElementType::TauG2 => self.g2_size(compression),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The parameters used for the trusted setup ceremony
pub struct CeremonyParams<E> {
    /// The type of the curve being used
    pub curve: CurveParams<E>,
    /// The number of Powers of Tau G1 elements which will be accumulated
    pub powers_g1_length: usize,
    /// The number of Powers of Tau Alpha/Beta/G2 elements which will be accumulated
    pub powers_length: usize,
    /// The circuit size exponent (ie length will be 2^size), depends on the computation you want to support
    pub size: usize,
    /// The empirical batch size for the batched accumulator.
    /// This is a hyper parameter and may be different for each
    /// curve.
    pub batch_size: usize,
    // Size of the used public key
    pub public_key_size: usize,
    /// Total size of the accumulator used for the ceremony
    pub accumulator_size: usize,
    /// Total size of the contribution
    pub contribution_size: usize,
    /// Size of the hash of the previous contribution
    pub hash_size: usize,
}

impl<E: PairingEngine> CeremonyParams<E> {
    /// Constructs a new ceremony parameters object from the type of provided curve
    /// Panics if given batch_size = 0
    pub fn new(size: usize, batch_size: usize) -> Self {
        // create the curve
        let curve = CurveParams::<E>::new();
        Self::new_with_curve(curve, size, batch_size)
    }

    /// Constructs a new ceremony parameters object from the directly provided curve with parameters
    /// Consider using the `new` method if you want to use one of the pre-implemented curves
    pub fn new_with_curve(curve: CurveParams<E>, size: usize, batch_size: usize) -> Self {
        // assume we're using a 64 byte long hash function such as Blake
        let hash_size = 64;

        // 2^{size}
        let powers_length = 1 << size;
        // 2^{size+1} - 1
        let powers_g1_length = (powers_length << 1) - 1;

        let accumulator_size =
            // G1 Tau powers
            powers_g1_length * curve.g1 +
            // G2 Tau Powers + Alpha Tau powers + Beta Tau powers
            powers_length * (curve.g2 + (curve.g1 * 2)) +
            // Beta in G2
            curve.g2 +
            // Hash of the previous contribution
            hash_size;

        let public_key_size =
           // tau, alpha, beta in g2
           3 * curve.g2 +
           // (s1, s1*tau), (s2, s2*alpha), (s3, s3*beta) in g1
           6 * curve.g1;

        let contribution_size =
            // G1 Tau powers (compressed)
            powers_g1_length * curve.g1_compressed +
            // G2 Tau Powers + Alpha Tau powers + Beta Tau powers (compressed)
            powers_length * (curve.g2_compressed + (curve.g1_compressed * 2)) +
            // Beta in G2
            curve.g2_compressed +
            // Hash of the previous contribution
            hash_size +
            // The public key of the previous contributor
            public_key_size;

        Self {
            curve,
            size,
            batch_size,
            accumulator_size,
            public_key_size,
            contribution_size,
            hash_size,
            powers_length,
            powers_g1_length,
        }
    }

    /// Returns the length of the serialized accumulator depending on if it's compressed or not
    pub fn get_length(&self, compressed: UseCompression) -> usize {
        match compressed {
            UseCompression::Yes => self.contribution_size - self.public_key_size,
            UseCompression::No => self.accumulator_size,
        }
    }
}

/// Determines if point compression should be used.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum UseCompression {
    Yes,
    No,
}

/// Determines if points should be checked for correctness during deserialization.
/// This is not necessary for participants, because a transcript verifier can
/// check this theirself.
#[derive(Copy, Clone, PartialEq)]
pub enum CheckForCorrectness {
    Yes,
    No,
}

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

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("Invalid ratio! Context: {0}")]
    /// The ratio check via the pairing of the provided elements failed
    InvalidRatio(&'static str),
    #[error("Invalid generator for {0} powers")]
    /// The first power of Tau was not the generator of that group
    InvalidGenerator(ElementType),
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ElementType {
    TauG1,
    TauG2,
    AlphaG1,
    BetaG1,
    BetaG2,
}

impl fmt::Display for UseCompression {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            UseCompression::Yes => write!(f, "Yes"),
            UseCompression::No => write!(f, "No"),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use zexe_algebra::curves::{bls12_377::Bls12_377, bls12_381::Bls12_381, sw6::SW6};

    #[test]
    fn params_sizes() {
        curve_params_test::<Bls12_377>(96, 192, 48, 96);
        curve_params_test::<Bls12_381>(96, 192, 48, 96);
        curve_params_test::<SW6>(196, 588, 98, 294);
    }

    fn curve_params_test<E: PairingEngine>(
        g1: usize,
        g2: usize,
        g1_compressed: usize,
        g2_compressed: usize,
    ) {
        let p = CurveParams::<E>::new();
        assert_eq!(p.g1, g1);
        assert_eq!(p.g2, g2);
        assert_eq!(p.g1_compressed, g1_compressed);
        assert_eq!(p.g2_compressed, g2_compressed);
    }
}
