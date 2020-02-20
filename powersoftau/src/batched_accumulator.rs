/// Memory constrained accumulator that checks parts of the initial information in parts that fit to memory
/// and then contributes to entropy in parts as well
use itertools::{Itertools, MinMaxResult::MinMax};
use log::{error, info};
use parking_lot::RwLock;
use std::sync::Arc;
use zexe_algebra::{AffineCurve, Field, PairingEngine as Engine, ProjectiveCurve, Zero};

use generic_array::GenericArray;

use typenum::consts::U64;

use super::keypair::{PrivateKey, PublicKey};
use super::parameters::{
    CeremonyParams, CheckForCorrectness, DeserializationError, ElementType, UseCompression,
};
use super::utils::{batch_exp, blank_hash, compute_g2_s, power_pairs, same_ratio};

use rayon::prelude::*;
use std::ops::MulAssign;

pub enum AccumulatorState {
    Empty,
    NonEmpty,
    Transformed,
}

/// The `BatchedAccumulator` is an object that participants of the ceremony contribute
/// randomness to. This object contains powers of trapdoor `tau` in G1 and in G2 over
/// fixed generators, and additionally in G1 over two other generators of exponents
/// `alpha` and `beta` over those fixed generators. In other words:
///
/// * (τ, τ<sup>2</sup>, ..., τ<sup>2<sup>22</sup> - 2</sup>, α, ατ, ατ<sup>2</sup>, ..., ατ<sup>2<sup>21</sup> - 1</sup>, β, βτ, βτ<sup>2</sup>, ..., βτ<sup>2<sup>21</sup> - 1</sup>)<sub>1</sub>
/// * (β, τ, τ<sup>2</sup>, ..., τ<sup>2<sup>21</sup> - 1</sup>)<sub>2</sub>
pub struct BatchedAccumulator<'a, E: Engine> {
    /// tau^0, tau^1, tau^2, ..., tau^{TAU_POWERS_G1_LENGTH - 1}
    pub tau_powers_g1: Vec<E::G1Affine>,
    /// tau^0, tau^1, tau^2, ..., tau^{TAU_POWERS_LENGTH - 1}
    pub tau_powers_g2: Vec<E::G2Affine>,
    /// alpha * tau^0, alpha * tau^1, alpha * tau^2, ..., alpha * tau^{TAU_POWERS_LENGTH - 1}
    pub alpha_tau_powers_g1: Vec<E::G1Affine>,
    /// beta * tau^0, beta * tau^1, beta * tau^2, ..., beta * tau^{TAU_POWERS_LENGTH - 1}
    pub beta_tau_powers_g1: Vec<E::G1Affine>,
    /// beta
    pub beta_g2: E::G2Affine,
    /// Hash chain hash
    pub hash: GenericArray<u8, U64>,
    /// The parameters used for the setup of this accumulator
    pub parameters: &'a CeremonyParams<E>,
}

impl<'a, E: Engine + Sync> BatchedAccumulator<'a, E> {
    pub fn empty(parameters: &'a CeremonyParams<E>) -> Self {
        Self {
            tau_powers_g1: vec![],
            tau_powers_g2: vec![],
            alpha_tau_powers_g1: vec![],
            beta_tau_powers_g1: vec![],
            beta_g2: E::G2Affine::zero(),
            hash: blank_hash(),
            parameters,
        }
    }

    /// File expected structure
    /// HASH_SIZE bytes for the hash of the contribution
    /// TAU_POWERS_G1_LENGTH of G1 points
    /// TAU_POWERS_LENGTH of G2 points
    /// TAU_POWERS_LENGTH of G1 points for alpha
    /// TAU_POWERS_LENGTH of G1 points for beta
    /// One G2 point for beta
    /// Public key appended to the end of file, but it's irrelevant for an accumulator itself
    fn calculate_position(
        &self,
        index: usize,
        element_type: ElementType,
        compression: UseCompression,
    ) -> Result<usize, DeserializationError> {
        let g1_size = self.parameters.curve.g1_size(compression);
        let g2_size = self.parameters.curve.g2_size(compression);
        let required_tau_g1_power = self.parameters.powers_g1_length;
        let required_power = self.parameters.powers_length;
        let parameters = &self.parameters;
        let position = match element_type {
            ElementType::TauG1 => {
                if index >= required_tau_g1_power {
                    return Err(DeserializationError::PositionError(
                        element_type,
                        required_tau_g1_power,
                        index,
                    ));
                }
                g1_size * index
            }
            ElementType::TauG2 => {
                if index >= required_power {
                    return Err(DeserializationError::PositionError(
                        element_type,
                        required_power,
                        index,
                    ));
                }
                g1_size * required_tau_g1_power + g2_size * index
            }
            ElementType::AlphaG1 => {
                if index >= required_power {
                    return Err(DeserializationError::PositionError(
                        element_type,
                        required_power,
                        index,
                    ));
                }
                g1_size * required_tau_g1_power + g2_size * required_power + g1_size * index
            }
            ElementType::BetaG1 => {
                if index >= required_power {
                    return Err(DeserializationError::PositionError(
                        element_type,
                        required_power,
                        index,
                    ));
                }
                g1_size * required_tau_g1_power
                    + g2_size * required_power
                    + g1_size * required_power
                    + g1_size * index
            }
            ElementType::BetaG2 => {
                g1_size * required_tau_g1_power
                    + g2_size * required_power
                    + g1_size * required_power
                    + g1_size * required_power
            }
        };

        // The element's position is offset by the hash's size
        Ok(parameters.hash_size + position)
    }

    /// Verifies a transformation of the `Accumulator` with the `PublicKey`, given a 64-byte transcript `digest`.
    #[allow(clippy::too_many_arguments, clippy::cognitive_complexity)]
    pub fn verify_transformation(
        input: &[u8],
        output: &[u8],
        key: &PublicKey<E>,
        digest: &[u8],
        input_is_compressed: UseCompression,
        output_is_compressed: UseCompression,
        check_input_for_correctness: CheckForCorrectness,
        check_output_for_correctness: CheckForCorrectness,
        parameters: &'a CeremonyParams<E>,
    ) -> bool {
        assert_eq!(digest.len(), 64);

        let tau_g2_s = compute_g2_s::<E>(&digest, &key.tau_g1.0, &key.tau_g1.1, 0);
        let alpha_g2_s = compute_g2_s::<E>(&digest, &key.alpha_g1.0, &key.alpha_g1.1, 1);
        let beta_g2_s = compute_g2_s::<E>(&digest, &key.beta_g1.0, &key.beta_g1.1, 2);

        // Check the proofs-of-knowledge for tau/alpha/beta

        // g1^s / g1^(s*x) = g2^s / g2^(s*x)
        if !same_ratio(key.tau_g1, (tau_g2_s, key.tau_g2)) {
            error!("Invalid ratio key.tau_g1, (tau_g2_s, key.tau_g2)");
            return false;
        }
        if !same_ratio(key.alpha_g1, (alpha_g2_s, key.alpha_g2)) {
            error!("Invalid ratio key.alpha_g1, (alpha_g2_s, key.alpha_g2)");
            return false;
        }
        if !same_ratio(key.beta_g1, (beta_g2_s, key.beta_g2)) {
            error!("Invalid ratio key.beta_g1, (beta_g2_s, key.beta_g2)");
            return false;
        }

        // Load accumulators AND perform computations

        let mut before = Self::empty(parameters);
        let mut after = Self::empty(parameters);

        // these checks only touch a part of the accumulator, so read two elements

        {
            let chunk_size = 2;
            before
                .read_chunk(
                    0,
                    chunk_size,
                    input_is_compressed,
                    check_input_for_correctness,
                    &input,
                )
                .expect("must read a first chunk from `challenge`");
            after
                .read_chunk(
                    0,
                    chunk_size,
                    output_is_compressed,
                    check_output_for_correctness,
                    &output,
                )
                .expect("must read a first chunk from `response`");

            // Check the correctness of the generators for tau powers
            if after.tau_powers_g1[0] != E::G1Affine::prime_subgroup_generator() {
                error!("tau_powers_g1[0] != 1");
                return false;
            }
            if after.tau_powers_g2[0] != E::G2Affine::prime_subgroup_generator() {
                error!("tau_powers_g2[0] != 1");
                return false;
            }

            // Did the participant multiply the previous tau by the new one?
            if !same_ratio(
                (before.tau_powers_g1[1], after.tau_powers_g1[1]),
                (tau_g2_s, key.tau_g2),
            ) {
                error!("Invalid ratio (before.tau_powers_g1[1], after.tau_powers_g1[1]), (tau_g2_s, key.tau_g2)");
                return false;
            }

            // Did the participant multiply the previous alpha by the new one?
            if !same_ratio(
                (before.alpha_tau_powers_g1[0], after.alpha_tau_powers_g1[0]),
                (alpha_g2_s, key.alpha_g2),
            ) {
                error!("Invalid ratio (before.alpha_tau_powers_g1[0], after.alpha_tau_powers_g1[0]), (alpha_g2_s, key.alpha_g2)");
                return false;
            }

            // Did the participant multiply the previous beta by the new one?
            if !same_ratio(
                (before.beta_tau_powers_g1[0], after.beta_tau_powers_g1[0]),
                (beta_g2_s, key.beta_g2),
            ) {
                error!("Invalid ratio (before.beta_tau_powers_g1[0], after.beta_tau_powers_g1[0]), (beta_g2_s, key.beta_g2)");
                return false;
            }
            if !same_ratio(
                (before.beta_tau_powers_g1[0], after.beta_tau_powers_g1[0]),
                (before.beta_g2, after.beta_g2),
            ) {
                error!("Invalid ratio (before.beta_tau_powers_g1[0], after.beta_tau_powers_g1[0]), (before.beta_g2, after.beta_g2)");
                return false;
            }
        }

        let tau_powers_g2_0 = after.tau_powers_g2[0];
        let tau_powers_g2_1 = after.tau_powers_g2[1];
        let tau_powers_g1_0 = after.tau_powers_g1[0];
        let tau_powers_g1_1 = after.tau_powers_g1[1];

        // Read by parts and just verify same ratios. Cause of two fixed variables above with tau_powers_g2_1 = tau_powers_g2_0 ^ s
        // one does not need to care about some overlapping

        let mut tau_powers_last_first_chunks = vec![E::G1Affine::zero(); 2];
        let tau_powers_length = parameters.powers_length;
        for chunk in &(0..tau_powers_length).chunks(parameters.batch_size) {
            if let MinMax(start, end) = chunk.minmax() {
                // extra 1 to ensure intersection between chunks and ensure we don't overflow
                let size = end - start + 1 + if end == tau_powers_length - 1 { 0 } else { 1 };
                before
                    .read_chunk(
                        start,
                        size,
                        input_is_compressed,
                        check_input_for_correctness,
                        &input,
                    )
                    .unwrap_or_else(|_| {
                        panic!(format!(
                            "must read a chunk from {} to {} from `challenge`",
                            start, end
                        ))
                    });
                after
                    .read_chunk(
                        start,
                        size,
                        output_is_compressed,
                        check_output_for_correctness,
                        &output,
                    )
                    .unwrap_or_else(|_| {
                        panic!(format!(
                            "must read a chunk from {} to {} from `response`",
                            start, end
                        ))
                    });

                // Are the powers of tau correct?
                if !same_ratio(
                    power_pairs(&after.tau_powers_g1),
                    (tau_powers_g2_0, tau_powers_g2_1),
                ) {
                    error!("Invalid ratio power_pairs(&after.tau_powers_g1), (tau_powers_g2_0, tau_powers_g2_1)");
                    return false;
                }
                if !same_ratio(
                    power_pairs(&after.tau_powers_g2),
                    (tau_powers_g1_0, tau_powers_g1_1),
                ) {
                    error!("Invalid ratio power_pairs(&after.tau_powers_g2), (tau_powers_g1_0, tau_powers_g1_1)");
                    return false;
                }
                if !same_ratio(
                    power_pairs(&after.alpha_tau_powers_g1),
                    (tau_powers_g2_0, tau_powers_g2_1),
                ) {
                    error!("Invalid ratio power_pairs(&after.alpha_tau_powers_g1), (tau_powers_g2_0, tau_powers_g2_1)");
                    return false;
                }
                if !same_ratio(
                    power_pairs(&after.beta_tau_powers_g1),
                    (tau_powers_g2_0, tau_powers_g2_1),
                ) {
                    error!("Invalid ratio power_pairs(&after.beta_tau_powers_g1), (tau_powers_g2_0, tau_powers_g2_1)");
                    return false;
                }
                if end == tau_powers_length - 1 {
                    tau_powers_last_first_chunks[0] = after.tau_powers_g1[size - 1];
                }
                info!("Done processing {} powers of tau", end);
            } else {
                panic!("Chunk does not have a min and max");
            }
        }

        for chunk in &(tau_powers_length..parameters.powers_g1_length).chunks(parameters.batch_size)
        {
            if let MinMax(start, end) = chunk.minmax() {
                // extra 1 to ensure intersection between chunks and ensure we don't overflow
                let size = end - start
                    + 1
                    + if end == parameters.powers_g1_length - 1 {
                        0
                    } else {
                        1
                    };
                before
                    .read_chunk(
                        start,
                        size,
                        input_is_compressed,
                        check_input_for_correctness,
                        &input,
                    )
                    .unwrap_or_else(|_| {
                        panic!(format!(
                            "must read a chunk from {} to {} from `challenge`",
                            start, end
                        ))
                    });
                after
                    .read_chunk(
                        start,
                        size,
                        output_is_compressed,
                        check_output_for_correctness,
                        &output,
                    )
                    .unwrap_or_else(|_| {
                        panic!(format!(
                            "must read a chunk from {} to {} from `response`",
                            start, end
                        ))
                    });

                assert_eq!(
                    before.tau_powers_g2.len(),
                    0,
                    "during rest of tau g1 generation tau g2 must be empty"
                );
                assert_eq!(
                    after.tau_powers_g2.len(),
                    0,
                    "during rest of tau g1 generation tau g2 must be empty"
                );

                // Are the powers of tau correct?
                if !same_ratio(
                    power_pairs(&after.tau_powers_g1),
                    (tau_powers_g2_0, tau_powers_g2_1),
                ) {
                    error!("Invalid ratio power_pairs(&after.tau_powers_g1), (tau_powers_g2_0, tau_powers_g2_1) in extra TauG1 contribution");
                    return false;
                }
                if start == parameters.powers_length {
                    tau_powers_last_first_chunks[1] = after.tau_powers_g1[0];
                }
                info!("Done processing {} powers of tau", end);
            } else {
                panic!("Chunk does not have a min and max");
            }
        }

        if !same_ratio(
            power_pairs(&tau_powers_last_first_chunks),
            (tau_powers_g2_0, tau_powers_g2_1),
        ) {
            error!("Invalid ratio power_pairs(&after.tau_powers_g1), (tau_powers_g2_0, tau_powers_g2_1) in TauG1 contribution intersection");
            return false;
        }

        true
    }

    pub fn decompress(
        input: &[u8],
        output: &mut [u8],
        check_input_for_correctness: CheckForCorrectness,
        parameters: &'a CeremonyParams<E>,
    ) -> Result<(), DeserializationError> {
        let mut accumulator = Self::empty(parameters);

        for chunk in &(0..parameters.powers_length).chunks(parameters.batch_size) {
            if let MinMax(start, end) = chunk.minmax() {
                let size = end - start + 1;
                accumulator
                    .read_chunk(
                        start,
                        size,
                        UseCompression::Yes,
                        check_input_for_correctness,
                        &input,
                    )
                    .unwrap_or_else(|_| {
                        panic!(format!(
                            "must read a chunk from {} to {} from source of decompression",
                            start, end
                        ))
                    });
                accumulator.write_chunk(start, UseCompression::No, output)?;
            } else {
                panic!("Chunk does not have a min and max");
            }
        }

        for chunk in
            &(parameters.powers_length..parameters.powers_g1_length).chunks(parameters.batch_size)
        {
            if let MinMax(start, end) = chunk.minmax() {
                let size = end - start + 1;
                accumulator
                    .read_chunk(
                        start,
                        size,
                        UseCompression::Yes,
                        check_input_for_correctness,
                        &input,
                    )
                    .unwrap_or_else(|_| {
                        panic!(format!(
                            "must read a chunk from {} to {} from source of decompression",
                            start, end
                        ))
                    });
                assert_eq!(
                    accumulator.tau_powers_g2.len(),
                    0,
                    "during rest of tau g1 generation tau g2 must be empty"
                );
                assert_eq!(
                    accumulator.alpha_tau_powers_g1.len(),
                    0,
                    "during rest of tau g1 generation alpha*tau in g1 must be empty"
                );
                assert_eq!(
                    accumulator.beta_tau_powers_g1.len(),
                    0,
                    "during rest of tau g1 generation beta*tau in g1 must be empty"
                );

                accumulator.write_chunk(start, UseCompression::No, output)?;
            } else {
                panic!("Chunk does not have a min and max");
            }
        }

        Ok(())
    }

    pub fn deserialize(
        input: &[u8],
        check_input_for_correctness: CheckForCorrectness,
        compression: UseCompression,
        parameters: &'a CeremonyParams<E>,
    ) -> Result<BatchedAccumulator<'a, E>, DeserializationError> {
        let mut accumulator = Self::empty(parameters);

        let mut tau_powers_g1 = vec![];
        let mut tau_powers_g2 = vec![];
        let mut alpha_tau_powers_g1 = vec![];
        let mut beta_tau_powers_g1 = vec![];
        let mut beta_g2 = vec![];

        for chunk in &(0..parameters.powers_length).chunks(parameters.batch_size) {
            if let MinMax(start, end) = chunk.minmax() {
                let size = end - start + 1;
                accumulator
                    .read_chunk(
                        start,
                        size,
                        compression,
                        check_input_for_correctness,
                        &input,
                    )
                    .unwrap_or_else(|_| {
                        panic!(format!(
                            "must read a chunk from {} to {} from source of decompression",
                            start, end
                        ))
                    });
                tau_powers_g1.extend_from_slice(&accumulator.tau_powers_g1);
                tau_powers_g2.extend_from_slice(&accumulator.tau_powers_g2);
                alpha_tau_powers_g1.extend_from_slice(&accumulator.alpha_tau_powers_g1);
                beta_tau_powers_g1.extend_from_slice(&accumulator.beta_tau_powers_g1);
                if start == 0 {
                    beta_g2.extend_from_slice(&[accumulator.beta_g2]);
                }
            } else {
                panic!("Chunk does not have a min and max");
            }
        }

        for chunk in
            &(parameters.powers_length..parameters.powers_g1_length).chunks(parameters.batch_size)
        {
            if let MinMax(start, end) = chunk.minmax() {
                let size = end - start + 1;
                accumulator
                    .read_chunk(
                        start,
                        size,
                        compression,
                        check_input_for_correctness,
                        &input,
                    )
                    .unwrap_or_else(|_| {
                        panic!(format!(
                            "must read a chunk from {} to {} from source of decompression",
                            start, end
                        ))
                    });
                assert_eq!(
                    accumulator.tau_powers_g2.len(),
                    0,
                    "during rest of tau g1 generation tau g2 must be empty"
                );
                assert_eq!(
                    accumulator.alpha_tau_powers_g1.len(),
                    0,
                    "during rest of tau g1 generation alpha*tau in g1 must be empty"
                );
                assert_eq!(
                    accumulator.beta_tau_powers_g1.len(),
                    0,
                    "during rest of tau g1 generation beta*tau in g1 must be empty"
                );

                tau_powers_g1.extend_from_slice(&accumulator.tau_powers_g1);
                tau_powers_g2.extend_from_slice(&accumulator.tau_powers_g2);
                alpha_tau_powers_g1.extend_from_slice(&accumulator.alpha_tau_powers_g1);
                beta_tau_powers_g1.extend_from_slice(&accumulator.beta_tau_powers_g1);
            } else {
                panic!("Chunk does not have a min and max");
            }
        }

        Ok(BatchedAccumulator {
            tau_powers_g1,
            tau_powers_g2,
            alpha_tau_powers_g1,
            beta_tau_powers_g1,
            beta_g2: beta_g2[0],
            hash: blank_hash(),
            parameters,
        })
    }

    pub fn serialize(
        &mut self,
        output: &mut [u8],
        compression: UseCompression,
        parameters: &CeremonyParams<E>,
    ) -> Result<(), DeserializationError> {
        for chunk in &(0..parameters.powers_length).chunks(parameters.batch_size) {
            if let MinMax(start, end) = chunk.minmax() {
                let tmp_acc = BatchedAccumulator::<E> {
                    tau_powers_g1: (&self.tau_powers_g1[start..=end]).to_vec(),
                    tau_powers_g2: (&self.tau_powers_g2[start..=end]).to_vec(),
                    alpha_tau_powers_g1: (&self.alpha_tau_powers_g1[start..=end]).to_vec(),
                    beta_tau_powers_g1: (&self.beta_tau_powers_g1[start..=end]).to_vec(),
                    beta_g2: self.beta_g2,
                    hash: self.hash,
                    parameters,
                };
                tmp_acc.write_chunk(start, compression, output)?;
            } else {
                panic!("Chunk does not have a min and max");
            }
        }

        for chunk in
            &(parameters.powers_length..parameters.powers_g1_length).chunks(parameters.batch_size)
        {
            if let MinMax(start, end) = chunk.minmax() {
                let tmp_acc = BatchedAccumulator::<E> {
                    tau_powers_g1: (&self.tau_powers_g1[start..=end]).to_vec(),
                    tau_powers_g2: vec![],
                    alpha_tau_powers_g1: vec![],
                    beta_tau_powers_g1: vec![],
                    beta_g2: self.beta_g2,
                    hash: self.hash,
                    parameters,
                };
                tmp_acc.write_chunk(start, compression, output)?;
            } else {
                panic!("Chunk does not have a min and max");
            }
        }

        Ok(())
    }

    pub fn read_chunk(
        &mut self,
        from: usize,
        size: usize,
        compression: UseCompression,
        checked: CheckForCorrectness,
        input: &[u8],
    ) -> Result<(), DeserializationError> {
        // Read `size` G1 Tau Elements
        self.tau_powers_g1 =
            self.read_points_chunk(&input, from, size, ElementType::TauG1, compression, checked)?;

        // Read `size` G2 Tau Elements
        self.tau_powers_g2 =
            self.read_points_chunk(&input, from, size, ElementType::TauG2, compression, checked)?;

        // Read `size` G1 Alpha Elements
        self.alpha_tau_powers_g1 = self.read_points_chunk(
            &input,
            from,
            size,
            ElementType::AlphaG1,
            compression,
            checked,
        )?;

        // Read `size` G1 Beta Elements
        self.beta_tau_powers_g1 = self.read_points_chunk(
            &input,
            from,
            size,
            ElementType::BetaG1,
            compression,
            checked,
        )?;

        // Read 1 G2 Beta Element
        self.beta_g2 =
            self.read_points_chunk(&input, 0, 1, ElementType::BetaG2, compression, checked)?[0];

        Ok(())
    }

    fn read_points_chunk<G: AffineCurve>(
        &self,
        input: &[u8],
        from: usize,
        size: usize,
        element_type: ElementType,
        compression: UseCompression,
        checked: CheckForCorrectness,
    ) -> Result<Vec<G>, DeserializationError> {
        let element_size = self.parameters.curve.get_size(element_type, compression);
        (from..from + size)
            .into_par_iter()
            .flat_map(|index| {
                // return empty vector if we are out of bounds
                // (we should not throw an error though!)
                if self.is_out_of_bounds(element_type, index) {
                    return None;
                }

                // get the slice corresponding to the element
                let position = match self.calculate_position(index, element_type, compression) {
                    Ok(p) => p,
                    Err(e) => return Some(Err(e)),
                };
                let chunk = &input[position..position + element_size];
                // read to a point
                let res = if compression == UseCompression::Yes {
                    G::deserialize(chunk, &mut [])
                } else {
                    G::deserialize_uncompressed(chunk)
                };
                let point = match res {
                    Ok(point) => point,
                    Err(e) => return Some(Err(e.into())),
                };

                Some(if point.is_zero() && checked == CheckForCorrectness::Yes {
                    Err(DeserializationError::PointAtInfinity)
                } else {
                    Ok(point)
                })
            })
            .collect()
    }

    fn is_out_of_bounds(&self, element_type: ElementType, index: usize) -> bool {
        match element_type {
            ElementType::TauG1 => {
                if index >= self.parameters.powers_g1_length {
                    return true;
                }
            }
            ElementType::AlphaG1
            | ElementType::BetaG1
            | ElementType::BetaG2
            | ElementType::TauG2 => {
                if index >= self.parameters.powers_length {
                    return true;
                }
            }
        };
        false
    }

    fn write_point<C>(
        &self,
        p: &C,
        output: &mut [u8],
        index: usize,
        compression: UseCompression,
        element_type: ElementType,
    ) -> Result<(), DeserializationError>
    where
        C: AffineCurve,
    {
        if self.is_out_of_bounds(element_type, index) {
            return Ok(());
        }

        let position = self.calculate_position(index, element_type, compression)?;
        let element_size = self.parameters.curve.get_size(element_type, compression);
        match compression {
            UseCompression::Yes => {
                p.serialize(&[], &mut output[position..position + element_size])?
            }
            UseCompression::No => {
                p.serialize_uncompressed(&mut output[position..position + element_size])?
            }
        };

        Ok(())
    }

    fn write_points_chunk(
        &self,
        elements: &[impl AffineCurve],
        output: &mut [u8],
        chunk_start: usize,
        compressed: UseCompression,
        element_type: ElementType,
    ) -> Result<(), DeserializationError> {
        let output = Arc::new(RwLock::new(output));
        // Does this provide significant performance benefits?
        elements.par_iter().enumerate().for_each(|(i, c)| {
            let index = chunk_start + i;
            if let Err(e) =
                self.write_point_sync(c, output.clone(), index, compressed, element_type)
            {
                log::error!("Error when writing point {:?}", e);
            }
        });
        Ok(())
    }

    fn write_point_sync<C>(
        &self,
        p: &C,
        output: Arc<RwLock<&mut [u8]>>,
        index: usize,
        compression: UseCompression,
        element_type: ElementType,
    ) -> Result<(), DeserializationError>
    where
        C: AffineCurve,
    {
        let output = &mut *output.write();
        self.write_point(p, output, index, compression, element_type)
    }

    /// Write the accumulator with some compression behavior.
    fn write_chunk(
        &self,
        chunk_start: usize,
        compression: UseCompression,
        output: &mut [u8],
    ) -> Result<(), DeserializationError> {
        // Write the G1 Tau elements
        self.write_points_chunk(
            &self.tau_powers_g1,
            output,
            chunk_start,
            compression,
            ElementType::TauG1,
        )?;

        if chunk_start < self.parameters.powers_length {
            // Write the G2 Tau elements
            self.write_points_chunk(
                &self.tau_powers_g2,
                output,
                chunk_start,
                compression,
                ElementType::TauG2,
            )?;
            // Write the G1 Alpha elements
            self.write_points_chunk(
                &self.alpha_tau_powers_g1,
                output,
                chunk_start,
                compression,
                ElementType::AlphaG1,
            )?;
            // Write the G1 Beta elements
            self.write_points_chunk(
                &self.beta_tau_powers_g1,
                output,
                chunk_start,
                compression,
                ElementType::BetaG1,
            )?;
            // Writes 1 G2 Beta element
            self.write_point(
                &self.beta_g2,
                output,
                chunk_start,
                compression,
                ElementType::BetaG2,
            )?
        }

        Ok(())
    }

    /// Transforms the accumulator with a private key.
    /// Due to large amount of data in a previous accumulator even in the compressed form
    /// this function can now work on compressed input. Output can be made in any form
    /// WARNING: Contributor does not have to check that values from challenge file were serialized
    /// correctly, but we may want to enforce it if a ceremony coordinator does not recompress the previous
    /// contribution into the new challenge file
    pub fn contribute(
        input: &[u8],
        output: &mut [u8],
        input_is_compressed: UseCompression,
        compress_the_output: UseCompression,
        check_input_for_correctness: CheckForCorrectness,
        key: &PrivateKey<E>,
        parameters: &'a CeremonyParams<E>,
    ) -> Result<(), DeserializationError> {
        let mut accumulator = Self::empty(parameters);

        for chunk in &(0..parameters.powers_length).chunks(parameters.batch_size) {
            if let MinMax(start, end) = chunk.minmax() {
                let size = end - start + 1;
                accumulator
                    .read_chunk(
                        start,
                        size,
                        input_is_compressed,
                        check_input_for_correctness,
                        &input,
                    )
                    .expect("must read a first chunk");

                // Construct the powers of tau
                let mut taupowers = vec![E::Fr::zero(); size];
                let chunk_size = size / num_cpus::get();

                // Construct exponents in parallel
                crossbeam::scope(|scope| {
                    for (i, taupowers) in taupowers.chunks_mut(chunk_size).enumerate() {
                        scope.spawn(move || {
                            let mut acc = key.tau.pow(&[(start + i * chunk_size) as u64]);

                            for t in taupowers {
                                *t = acc;
                                acc.mul_assign(&key.tau);
                            }
                        });
                    }
                });

                batch_exp(&mut accumulator.tau_powers_g1, &taupowers[0..], None);
                batch_exp(&mut accumulator.tau_powers_g2, &taupowers[0..], None);
                batch_exp(
                    &mut accumulator.alpha_tau_powers_g1,
                    &taupowers[0..],
                    Some(&key.alpha),
                );
                batch_exp(
                    &mut accumulator.beta_tau_powers_g1,
                    &taupowers[0..],
                    Some(&key.beta),
                );
                accumulator.beta_g2 = accumulator.beta_g2.mul(key.beta).into_affine();
                assert!(
                    !accumulator.beta_g2.is_zero(),
                    "your contribution happened to produce a point at infinity, please re-run"
                );
                accumulator.write_chunk(start, compress_the_output, output)?;
                info!("Done processing {} powers of tau", end);
            } else {
                panic!("Chunk does not have a min and max");
            }
        }

        for chunk in
            &(parameters.powers_length..parameters.powers_g1_length).chunks(parameters.batch_size)
        {
            if let MinMax(start, end) = chunk.minmax() {
                let size = end - start + 1;
                accumulator
                    .read_chunk(
                        start,
                        size,
                        input_is_compressed,
                        check_input_for_correctness,
                        &input,
                    )
                    .expect("must read a first chunk");
                assert_eq!(
                    accumulator.tau_powers_g2.len(),
                    0,
                    "during rest of tau g1 generation tau g2 must be empty"
                );

                // Construct the powers of tau
                let mut taupowers = vec![E::Fr::zero(); size];
                let chunk_size = size / num_cpus::get();

                // Construct exponents in parallel
                crossbeam::scope(|scope| {
                    for (i, taupowers) in taupowers.chunks_mut(chunk_size).enumerate() {
                        scope.spawn(move || {
                            let mut acc = key.tau.pow(&[(start + i * chunk_size) as u64]);

                            for t in taupowers {
                                *t = acc;
                                acc.mul_assign(&key.tau);
                            }
                        });
                    }
                });

                batch_exp(&mut accumulator.tau_powers_g1, &taupowers[0..], None);
                //accumulator.beta_g2 = accumulator.beta_g2.mul(key.beta).into_affine();
                //assert!(!accumulator.beta_g2.is_zero(), "your contribution happened to produce a point at infinity, please re-run");
                accumulator.write_chunk(start, compress_the_output, output)?;

                info!("Done processing {} powers of tau", end);
            } else {
                panic!("Chunk does not have a min and max");
            }
        }

        Ok(())
    }

    /// Transforms the accumulator with a private key.
    pub fn generate_initial(
        output: &mut [u8],
        compress_the_output: UseCompression,
        parameters: &'a CeremonyParams<E>,
    ) -> Result<(), DeserializationError> {
        // Write the first Tau powers in chunks where every initial element is a G1 or G2 `one`
        for chunk in &(0..parameters.powers_length).chunks(parameters.batch_size) {
            if let MinMax(start, end) = chunk.minmax() {
                let size = end - start + 1;
                let accumulator = Self {
                    tau_powers_g1: vec![E::G1Affine::prime_subgroup_generator(); size],
                    tau_powers_g2: vec![E::G2Affine::prime_subgroup_generator(); size],
                    alpha_tau_powers_g1: vec![E::G1Affine::prime_subgroup_generator(); size],
                    beta_tau_powers_g1: vec![E::G1Affine::prime_subgroup_generator(); size],
                    beta_g2: E::G2Affine::prime_subgroup_generator(),
                    hash: blank_hash(),
                    parameters,
                };

                accumulator.write_chunk(start, compress_the_output, output)?;
                info!("Done processing {} powers of tau", end);
            } else {
                panic!("Chunk does not have a min and max");
            }
        }

        // Write the next `G1 length` elements
        for chunk in
            &(parameters.powers_length..parameters.powers_g1_length).chunks(parameters.batch_size)
        {
            if let MinMax(start, end) = chunk.minmax() {
                let size = end - start + 1;
                let accumulator = Self {
                    tau_powers_g1: vec![E::G1Affine::prime_subgroup_generator(); size],
                    tau_powers_g2: vec![],
                    alpha_tau_powers_g1: vec![],
                    beta_tau_powers_g1: vec![],
                    beta_g2: E::G2Affine::prime_subgroup_generator(),
                    hash: blank_hash(),
                    parameters,
                };

                accumulator.write_chunk(start, compress_the_output, output)?;
                info!("Done processing {} powers of tau", end);
            } else {
                panic!("Chunk does not have a min and max");
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        parameters::CurveParams,
        utils::test_helpers::{random_point, random_point_vec, random_point_vec_batched},
    };
    use rand::thread_rng;
    use zexe_algebra::curves::{bls12_377::Bls12_377, bls12_381::Bls12_381, sw6::SW6};

    #[test]
    fn serializer_bls12_381() {
        serialize_accumulator_curve::<Bls12_381>(UseCompression::Yes);
        serialize_accumulator_curve::<Bls12_381>(UseCompression::No);
    }

    #[test]
    fn serializer_bls12_377() {
        serialize_accumulator_curve::<Bls12_377>(UseCompression::Yes);
        serialize_accumulator_curve::<Bls12_377>(UseCompression::No);
    }

    #[test]
    #[ignore] // this takes very long to run
    fn serializer_sw6() {
        serialize_accumulator_curve::<SW6>(UseCompression::Yes);
        serialize_accumulator_curve::<SW6>(UseCompression::No);
    }

    fn serialize_accumulator_curve<E: Engine + Sync>(compress: UseCompression) {
        // create a small accumulator with some random state
        let curve = CurveParams::<E>::new();
        let parameters = CeremonyParams::new_with_curve(curve, 2, 4);
        let mut accumulator = random_accumulator::<E>(&parameters);

        let expected_challenge_length = match compress {
            UseCompression::Yes => parameters.contribution_size - parameters.public_key_size,
            UseCompression::No => parameters.accumulator_size,
        };
        let mut buffer = vec![0; expected_challenge_length];

        // serialize it and ensure that the recovered version matches the original
        accumulator
            .serialize(&mut buffer, compress, &parameters)
            .unwrap();
        let deserialized = BatchedAccumulator::deserialize(
            &buffer,
            CheckForCorrectness::Yes,
            compress,
            &parameters,
        )
        .unwrap();

        assert_eq!(deserialized.tau_powers_g1, accumulator.tau_powers_g1);
        assert_eq!(deserialized.tau_powers_g2, accumulator.tau_powers_g2);
        assert_eq!(
            deserialized.alpha_tau_powers_g1,
            accumulator.alpha_tau_powers_g1
        );
        assert_eq!(
            deserialized.beta_tau_powers_g1,
            accumulator.beta_tau_powers_g1
        );
        assert_eq!(deserialized.beta_g2, accumulator.beta_g2);
    }

    #[test]
    fn read_write_chunk_bls_12_381() {
        // ensure that serializing and deserializing works for varying batch sizes and powers
        // todo: add benchmarks to this so that we can figure out optimal batch sizes for each curve
        read_write_chunk_curve::<Bls12_381>(3, 6, UseCompression::Yes);
        read_write_chunk_curve::<Bls12_381>(5, 2, UseCompression::Yes);
        read_write_chunk_curve::<Bls12_381>(3, 6, UseCompression::No);
        read_write_chunk_curve::<Bls12_381>(5, 2, UseCompression::No);
    }

    #[test]
    fn read_write_chunk_bls_12_377() {
        read_write_chunk_curve::<Bls12_377>(3, 6, UseCompression::Yes);
        read_write_chunk_curve::<Bls12_377>(5, 2, UseCompression::Yes);
        read_write_chunk_curve::<Bls12_377>(3, 6, UseCompression::No);
        read_write_chunk_curve::<Bls12_377>(5, 2, UseCompression::No);
    }

    #[test]
    fn read_write_chunk_sw6() {
        read_write_chunk_curve::<SW6>(3, 6, UseCompression::Yes);
        read_write_chunk_curve::<SW6>(5, 2, UseCompression::Yes);
        read_write_chunk_curve::<SW6>(3, 6, UseCompression::No);
        read_write_chunk_curve::<SW6>(5, 2, UseCompression::No);
    }

    fn read_write_chunk_curve<E: Engine + Sync>(
        powers: usize,
        batch_size: usize,
        compressed: UseCompression,
    ) {
        // we have a giant ceremony with N powers and 2N-1 tau_g1 elements which we want to split in batches of $batch_size
        let params = CeremonyParams::<E>::new(powers, batch_size);
        let acc = &BatchedAccumulator::empty(&params);
        let rng = &mut thread_rng();

        let tau_g1_powers = params.powers_g1_length;
        let other_powers = params.powers_length;

        // assume we have a huge buffer which can handle all operations. in practice, this will be
        // something like a MMap which can be lazily evaluated
        let mut buffer = vec![0; params.accumulator_size];

        // generate our G1 batches for TauG1
        let tau_g1: Vec<Vec<E::G1Affine>> =
            random_point_vec_batched(tau_g1_powers, batch_size, rng);
        // let's also serialize some Tau G2 points
        let tau_g2: Vec<Vec<E::G2Affine>> = random_point_vec_batched(other_powers, batch_size, rng);
        let alpha_g1: Vec<Vec<E::G1Affine>> =
            random_point_vec_batched(other_powers, batch_size, rng);
        let beta_g1: Vec<Vec<E::G1Affine>> =
            random_point_vec_batched(other_powers, batch_size, rng);

        // serialize them (we do all together to ensure that there is no part of the buffer which gets overwritten)
        serialize_batches(
            acc,
            &mut buffer,
            &tau_g1,
            batch_size,
            ElementType::TauG1,
            compressed,
        );
        serialize_batches(
            acc,
            &mut buffer,
            &tau_g2,
            batch_size,
            ElementType::TauG2,
            compressed,
        );
        serialize_batches(
            acc,
            &mut buffer,
            &alpha_g1,
            batch_size,
            ElementType::AlphaG1,
            compressed,
        );
        serialize_batches(
            acc,
            &mut buffer,
            &beta_g1,
            batch_size,
            ElementType::BetaG1,
            compressed,
        );

        // deserialize the buffer in batches
        let deserialized_tau_g1: Vec<Vec<E::G1Affine>> = deserialize_batches(
            acc,
            &buffer,
            tau_g1_powers,
            batch_size,
            ElementType::TauG1,
            compressed,
        );
        let deserialized_tau_g2: Vec<Vec<E::G2Affine>> = deserialize_batches(
            acc,
            &buffer,
            other_powers,
            batch_size,
            ElementType::TauG2,
            compressed,
        );
        let deserialized_alpha_g1: Vec<Vec<E::G1Affine>> = deserialize_batches(
            acc,
            &buffer,
            other_powers,
            batch_size,
            ElementType::AlphaG1,
            compressed,
        );
        let deserialized_beta_g1: Vec<Vec<E::G1Affine>> = deserialize_batches(
            acc,
            &buffer,
            other_powers,
            batch_size,
            ElementType::BetaG1,
            compressed,
        );
        assert_eq!(tau_g1, deserialized_tau_g1);
        assert_eq!(tau_g2, deserialized_tau_g2);
        assert_eq!(alpha_g1, deserialized_alpha_g1);
        assert_eq!(beta_g1, deserialized_beta_g1);
    }

    #[test]
    fn calculate_position_test() {
        fn test_position<'a, E: Engine + Sync>(
            acc: &BatchedAccumulator<'a, E>,
            index: usize,
            element_type: ElementType,
            compression: UseCompression,
            expected: usize,
        ) {
            let pos = acc
                .calculate_position(index, element_type, compression)
                .unwrap();
            // offset by 64 for the blake2b hash size
            assert_eq!(pos, expected + 64);
        }

        // Ensure that indexes greater than allowed produce an error
        fn index_out_of_bounds<'a, E: Engine + Sync>(
            acc: &BatchedAccumulator<'a, E>,
            length: usize,
            element: ElementType,
        ) {
            acc.calculate_position(length + 1, element, UseCompression::No)
                .unwrap_err();
            acc.calculate_position(length + 1, element, UseCompression::Yes)
                .unwrap_err();
        }

        let params = CeremonyParams::<Bls12_381>::new(10, 100);
        let acc = &BatchedAccumulator::empty(&params);
        let g1 = &params.curve.g1;
        let g1_c = params.curve.g1_compressed;
        let g2 = &params.curve.g2;
        let g2_c = params.curve.g2_compressed;
        let index = 1000;

        // TauG1 are just offset by their index
        let expected = g1 * index;
        test_position(acc, index, ElementType::TauG1, UseCompression::No, expected);
        let expected = g1_c * index;
        test_position(
            acc,
            index,
            ElementType::TauG1,
            UseCompression::Yes,
            expected,
        );

        // TauG2 elements follow the TauG1 elements
        let expected = g1 * params.powers_g1_length + g2 * index;
        test_position(acc, index, ElementType::TauG2, UseCompression::No, expected);
        let expected = g1_c * params.powers_g1_length + g2_c * index;
        test_position(
            acc,
            index,
            ElementType::TauG2,
            UseCompression::Yes,
            expected,
        );

        // AlphaG1 elements follow the TauG2 elements
        let expected = g1 * (params.powers_g1_length + index) + g2 * params.powers_length;
        test_position(
            acc,
            index,
            ElementType::AlphaG1,
            UseCompression::No,
            expected,
        );
        let expected = g1_c * (params.powers_g1_length + index) + g2_c * params.powers_length;
        test_position(
            acc,
            index,
            ElementType::AlphaG1,
            UseCompression::Yes,
            expected,
        );

        // BetaG1 elements follow the AlphaG1 elements
        let expected = g1 * (params.powers_g1_length + index) + (g1 + g2) * params.powers_length;
        test_position(
            acc,
            index,
            ElementType::BetaG1,
            UseCompression::No,
            expected,
        );
        let expected =
            g1_c * (params.powers_g1_length + index) + (g1_c + g2_c) * params.powers_length;
        test_position(
            acc,
            index,
            ElementType::BetaG1,
            UseCompression::Yes,
            expected,
        );

        // The BetaG2 element is 1 element right after the BetaG1, independently of index
        let expected = g1 * params.powers_g1_length + (2 * g1 + g2) * params.powers_length;
        test_position(
            acc,
            index,
            ElementType::BetaG2,
            UseCompression::No,
            expected,
        );
        test_position(acc, 0, ElementType::BetaG2, UseCompression::No, expected);
        test_position(
            acc,
            1_000_000_000,
            ElementType::BetaG2,
            UseCompression::No,
            expected,
        );
        let expected = g1_c * params.powers_g1_length + (2 * g1_c + g2_c) * params.powers_length;
        test_position(
            acc,
            index,
            ElementType::BetaG2,
            UseCompression::Yes,
            expected,
        );
        test_position(acc, 0, ElementType::BetaG2, UseCompression::Yes, expected);
        test_position(
            acc,
            1_000_000_000,
            ElementType::BetaG2,
            UseCompression::Yes,
            expected,
        );

        index_out_of_bounds(acc, params.powers_g1_length, ElementType::TauG1);
        index_out_of_bounds(acc, params.powers_length, ElementType::TauG2);
        index_out_of_bounds(acc, params.powers_length, ElementType::AlphaG1);
        index_out_of_bounds(acc, params.powers_length, ElementType::BetaG1);
    }

    // Helpers
    fn random_accumulator<'a, E: Engine>(
        parameters: &'a CeremonyParams<E>,
    ) -> BatchedAccumulator<'a, E> {
        let tau_g1_size = parameters.powers_g1_length;
        let other_size = parameters.powers_length;
        let rng = &mut thread_rng();
        BatchedAccumulator {
            tau_powers_g1: random_point_vec(tau_g1_size, rng),
            tau_powers_g2: random_point_vec(other_size, rng),
            alpha_tau_powers_g1: random_point_vec(other_size, rng),
            beta_tau_powers_g1: random_point_vec(other_size, rng),
            beta_g2: random_point(rng),
            hash: blank_hash(),
            parameters,
        }
    }

    fn serialize_batches<'a, C: AffineCurve, E: Engine + Sync>(
        acc: &BatchedAccumulator<'a, E>,
        buffer: &mut [u8],
        batches: &[Vec<C>],
        batch_size: usize,
        element_type: ElementType,
        compressed: UseCompression,
    ) {
        for (i, batch) in batches.iter().enumerate() {
            let chunk_start = i * batch_size;
            acc.write_points_chunk(&batch, buffer, chunk_start, compressed, element_type)
                .unwrap();
        }
    }

    fn deserialize_batches<'a, C: AffineCurve, E: Engine + Sync>(
        acc: &BatchedAccumulator<'a, E>,
        buffer: &[u8],
        size: usize,
        batch_size: usize,
        element_type: ElementType,
        compressed: UseCompression,
    ) -> Vec<Vec<C>> {
        let div = size / batch_size;
        let remainder = size % batch_size;
        let mut deserialized_batches: Vec<Vec<C>> = Vec::new();
        for i in 0..div {
            let chunk_start = i * batch_size;
            let batch: Vec<C> = acc
                .read_points_chunk(
                    &buffer,
                    chunk_start,
                    batch_size,
                    element_type,
                    compressed,
                    CheckForCorrectness::Yes,
                )
                .unwrap();
            deserialized_batches.push(batch);
        }
        if remainder > 0 {
            let chunk_start = div * batch_size;
            let batch: Vec<C> = acc
                .read_points_chunk(
                    &buffer,
                    chunk_start,
                    remainder,
                    element_type,
                    compressed,
                    CheckForCorrectness::Yes,
                )
                .unwrap();
            deserialized_batches.push(batch);
        }

        deserialized_batches
    }
}
