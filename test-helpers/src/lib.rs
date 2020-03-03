//! Helpers crate to be consumed in tests and benchmarks
mod accumulator_helpers;
pub use accumulator_helpers::{generate_input, generate_output, setup_verify};

mod fixtures;
pub use fixtures::TestCircuit;

use rand::{thread_rng, Rng};
use zexe_algebra::{AffineCurve, ProjectiveCurve, UniformRand};

pub use snark_utils::UseCompression;
use snark_utils::{buffer_size, Serializer}; // re-export for testing reasons

/// returns a random affine curve point from the provided rng
pub fn random_point<C: AffineCurve>(rng: &mut impl Rng) -> C {
    C::Projective::rand(rng).into_affine()
}

/// returns a random affine curve point vector from the provided rng
pub fn random_point_vec<C: AffineCurve>(size: usize, rng: &mut impl Rng) -> Vec<C> {
    (0..size).map(|_| random_point(rng)).collect()
}

/// returns a random affine curve point vector and serializes it
/// to a buffer with the provided compression format
pub fn random_vec_buf<C: AffineCurve>(
    size: usize,
    compression: UseCompression,
) -> (Vec<C>, Vec<u8>) {
    let mut rng = thread_rng();
    let elements: Vec<C> = random_point_vec(size, &mut rng);
    let len = buffer_size::<C>(compression) * size;
    let mut buf = vec![0; len];
    buf.write_batch(&elements, compression).unwrap();
    (elements, buf)
}

/// returns a random affine curve point vector and
/// returns an empty buffer with sufficient size
/// to write that vector to it
pub fn random_vec_empty_buf<C: AffineCurve>(
    size: usize,
    compression: UseCompression,
) -> (Vec<C>, Vec<u8>) {
    let mut rng = thread_rng();
    let elements: Vec<C> = random_point_vec(size, &mut rng);
    let len = buffer_size::<C>(compression) * size;
    let buf = vec![0; len];
    (elements, buf)
}
