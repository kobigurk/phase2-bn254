use bellman_ce::pairing::{CurveAffine, EncodedPoint, Engine, GroupDecodingError};
use std::fmt;
use std::io;
use std::marker::PhantomData;

/// The sizes of the group elements of a curev
#[derive(Clone, PartialEq, Eq, Default)]
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

impl<E: Engine> CurveParams<E> {
    pub fn new() -> CurveParams<E> {
        let g1 = <<E as Engine>::G1Affine as CurveAffine>::Uncompressed::size();
        let g2 = <<E as Engine>::G2Affine as CurveAffine>::Uncompressed::size();
        let g1_compressed = <<E as Engine>::G1Affine as CurveAffine>::Compressed::size();
        let g2_compressed = <<E as Engine>::G2Affine as CurveAffine>::Compressed::size();

        CurveParams {
            g1,
            g2,
            g1_compressed,
            g2_compressed,
            engine_type: PhantomData,
        }
    }

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

#[derive(Clone, PartialEq, Eq)]
/// The parameters used for the trusted setup ceremony
pub struct CeremonyParams<E> {
    /// The type of the curve being used (currently only supports BN256)
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

impl<E: Engine> CeremonyParams<E> {
    /// Constructs a new ceremony parameters object from the type of provided curve
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
}

// TODO: Add tests!

/// Determines if point compression should be used.
#[derive(Copy, Clone, PartialEq)]
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
#[derive(Debug)]
pub enum DeserializationError {
    IoError(io::Error),
    DecodingError(GroupDecodingError),
    PointAtInfinity,
}

impl fmt::Display for DeserializationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DeserializationError::IoError(ref e) => write!(f, "Disk IO error: {}", e),
            DeserializationError::DecodingError(ref e) => write!(f, "Decoding error: {}", e),
            DeserializationError::PointAtInfinity => write!(f, "Point at infinity found"),
        }
    }
}

impl From<io::Error> for DeserializationError {
    fn from(err: io::Error) -> DeserializationError {
        DeserializationError::IoError(err)
    }
}

impl From<GroupDecodingError> for DeserializationError {
    fn from(err: GroupDecodingError) -> DeserializationError {
        DeserializationError::DecodingError(err)
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
