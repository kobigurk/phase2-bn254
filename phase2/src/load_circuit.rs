use algebra::{CanonicalDeserialize, CanonicalSerialize, PairingEngine, SerializationError};
use r1cs_core::Matrix;
use setup_utils::Error;
use std::io::{Read, Write};

// For serialization of the constraint system
#[derive(Debug, PartialEq, CanonicalDeserialize, CanonicalSerialize, Clone)]
pub struct Matrices<E: PairingEngine> {
    /// The number of variables that are "public instances" to the constraint
    /// system.
    pub num_instance_variables: usize,
    /// The number of variables that are "private witnesses" to the constraint
    /// system.
    pub num_witness_variables: usize,
    /// The number of constraints in the constraint system.
    pub num_constraints: usize,
    /// The number of non_zero entries in the A matrix.
    pub a_num_non_zero: usize,
    /// The number of non_zero entries in the B matrix.
    pub b_num_non_zero: usize,
    /// The number of non_zero entries in the C matrix.
    pub c_num_non_zero: usize,
    /// The A constraint matrix. This is empty when
    /// `self.mode == SynthesisMode::Prove { construct_matrices = false }`.
    pub a: Matrix<E::Fr>,
    /// The B constraint matrix. This is empty when
    /// `self.mode == SynthesisMode::Prove { construct_matrices = false }`.
    pub b: Matrix<E::Fr>,
    /// The C constraint matrix. This is empty when
    /// `self.mode == SynthesisMode::Prove { construct_matrices = false }`.
    pub c: Matrix<E::Fr>,
}

impl<E: PairingEngine> Matrices<E> {
    pub fn read(input_map: &[u8]) -> Result<Self, Error> {
        Ok(Matrices::deserialize(&mut &input_map[..])?)
    }
}
