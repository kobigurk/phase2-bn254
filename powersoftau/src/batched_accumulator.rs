/// Memory constrained accumulator that checks parts of the initial information in parts that fit to memory
/// and then contributes to entropy in parts as well
use bellman_ce::pairing::ff::{Field, PrimeField};
use bellman_ce::pairing::*;
use itertools::{Itertools, MinMaxResult::MinMax};
use log::{error, info};

use generic_array::GenericArray;

use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};
use typenum::consts::U64;

use super::keypair::{PrivateKey, PublicKey};
use super::parameters::{
    CeremonyParams, CheckForCorrectness, DeserializationError, ElementType, UseCompression,
};
use super::utils::{blank_hash, compute_g2_s, power_pairs, same_ratio};

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

impl<'a, E: Engine> BatchedAccumulator<'a, E> {
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

    fn g1_size(&self, compression: UseCompression) -> usize {
        match compression {
            UseCompression::Yes => self.parameters.curve.g1_compressed,
            UseCompression::No => self.parameters.curve.g1,
        }
    }

    fn g2_size(&self, compression: UseCompression) -> usize {
        match compression {
            UseCompression::Yes => self.parameters.curve.g2_compressed,
            UseCompression::No => self.parameters.curve.g2,
        }
    }

    fn get_size(&self, element_type: ElementType, compression: UseCompression) -> usize {
        match element_type {
            ElementType::AlphaG1 | ElementType::BetaG1 | ElementType::TauG1 => {
                self.g1_size(compression)
            }
            ElementType::BetaG2 | ElementType::TauG2 => self.g2_size(compression),
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
    ) -> usize {
        let g1_size = self.g1_size(compression);
        let g2_size = self.g2_size(compression);
        let required_tau_g1_power = self.parameters.powers_g1_length;
        let required_power = self.parameters.powers_length;
        let parameters = &self.parameters;
        let position = match element_type {
            ElementType::TauG1 => {
                let mut position = 0;
                position += g1_size * index;
                assert!(
                    index < parameters.powers_g1_length,
                    format!(
                        "Index of TauG1 element written must not exceed {}, while it's {}",
                        parameters.powers_g1_length, index
                    )
                );

                position
            }
            ElementType::TauG2 => {
                let mut position = 0;
                position += g1_size * required_tau_g1_power;
                assert!(
                    index < required_power,
                    format!(
                        "Index of TauG2 element written must not exceed {}, while it's {}",
                        required_power, index
                    )
                );
                position += g2_size * index;

                position
            }
            ElementType::AlphaG1 => {
                let mut position = 0;
                position += g1_size * required_tau_g1_power;
                position += g2_size * required_power;
                assert!(
                    index < required_power,
                    format!(
                        "Index of AlphaG1 element written must not exceed {}, while it's {}",
                        required_power, index
                    )
                );
                position += g1_size * index;

                position
            }
            ElementType::BetaG1 => {
                let mut position = 0;
                position += g1_size * required_tau_g1_power;
                position += g2_size * required_power;
                position += g1_size * required_power;
                assert!(
                    index < required_power,
                    format!(
                        "Index of BetaG1 element written must not exceed {}, while it's {}",
                        required_power, index
                    )
                );
                position += g1_size * index;

                position
            }
            ElementType::BetaG2 => {
                let mut position = 0;
                position += g1_size * required_tau_g1_power;
                position += g2_size * required_power;
                position += g1_size * required_power;
                position += g1_size * required_power;

                position
            }
        };

        position + self.parameters.hash_size
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
            if after.tau_powers_g1[0] != E::G1Affine::one() {
                error!("tau_powers_g1[0] != 1");
                return false;
            }
            if after.tau_powers_g2[0] != E::G2Affine::one() {
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
        }
        true
    }

    pub fn decompress(
        input: &[u8],
        output: &mut [u8],
        check_input_for_correctness: CheckForCorrectness,
        parameters: &'a CeremonyParams<E>,
    ) -> io::Result<()> {
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
    ) -> io::Result<BatchedAccumulator<'a, E>> {
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
    ) -> io::Result<()> {
        for chunk in &(0..parameters.powers_length).chunks(parameters.batch_size) {
            if let MinMax(start, end) = chunk.minmax() {
                let mut tmp_acc = BatchedAccumulator::<E> {
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
                let mut tmp_acc = BatchedAccumulator::<E> {
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
        self.tau_powers_g1 = match compression {
            UseCompression::Yes => self
                .read_points_chunk::<<E::G1Affine as CurveAffine>::Compressed>(
                    from,
                    size,
                    ElementType::TauG1,
                    compression,
                    checked,
                    &input,
                )?,
            UseCompression::No => self
                .read_points_chunk::<<E::G1Affine as CurveAffine>::Uncompressed>(
                    from,
                    size,
                    ElementType::TauG1,
                    compression,
                    checked,
                    &input,
                )?,
        };

        self.tau_powers_g2 = match compression {
            UseCompression::Yes => self
                .read_points_chunk::<<E::G2Affine as CurveAffine>::Compressed>(
                    from,
                    size,
                    ElementType::TauG2,
                    compression,
                    checked,
                    &input,
                )?,
            UseCompression::No => self
                .read_points_chunk::<<E::G2Affine as CurveAffine>::Uncompressed>(
                    from,
                    size,
                    ElementType::TauG2,
                    compression,
                    checked,
                    &input,
                )?,
        };

        self.alpha_tau_powers_g1 = match compression {
            UseCompression::Yes => self
                .read_points_chunk::<<E::G1Affine as CurveAffine>::Compressed>(
                    from,
                    size,
                    ElementType::AlphaG1,
                    compression,
                    checked,
                    &input,
                )?,
            UseCompression::No => self
                .read_points_chunk::<<E::G1Affine as CurveAffine>::Uncompressed>(
                    from,
                    size,
                    ElementType::AlphaG1,
                    compression,
                    checked,
                    &input,
                )?,
        };

        self.beta_tau_powers_g1 = match compression {
            UseCompression::Yes => self
                .read_points_chunk::<<E::G1Affine as CurveAffine>::Compressed>(
                    from,
                    size,
                    ElementType::BetaG1,
                    compression,
                    checked,
                    &input,
                )?,
            UseCompression::No => self
                .read_points_chunk::<<E::G1Affine as CurveAffine>::Uncompressed>(
                    from,
                    size,
                    ElementType::BetaG1,
                    compression,
                    checked,
                    &input,
                )?,
        };

        self.beta_g2 = match compression {
            UseCompression::Yes => {
                let points = self.read_points_chunk::<<E::G2Affine as CurveAffine>::Compressed>(
                    0,
                    1,
                    ElementType::BetaG2,
                    compression,
                    checked,
                    &input,
                )?;

                points[0]
            }
            UseCompression::No => {
                let points = self.read_points_chunk::<<E::G2Affine as CurveAffine>::Uncompressed>(
                    0,
                    1,
                    ElementType::BetaG2,
                    compression,
                    checked,
                    &input,
                )?;

                points[0]
            }
        };

        Ok(())
    }

    fn read_points_chunk<ENC: EncodedPoint>(
        &mut self,
        from: usize,
        size: usize,
        element_type: ElementType,
        compression: UseCompression,
        checked: CheckForCorrectness,
        input: &[u8],
    ) -> Result<Vec<ENC::Affine>, DeserializationError> {
        // Read the encoded elements
        let mut res = vec![ENC::empty(); size];

        for (i, encoded) in res.iter_mut().enumerate() {
            let index = from + i;
            match element_type {
                ElementType::TauG1 => {
                    if index >= self.parameters.powers_g1_length {
                        return Ok(vec![]);
                    }
                }
                ElementType::AlphaG1
                | ElementType::BetaG1
                | ElementType::BetaG2
                | ElementType::TauG2 => {
                    if index >= self.parameters.powers_length {
                        return Ok(vec![]);
                    }
                }
            };
            let position = self.calculate_position(index, element_type, compression);
            let element_size = self.get_size(element_type, compression);
            let mut memory_slice = input
                .get(position..position + element_size)
                .expect("must read point data from file");
            memory_slice.read_exact(encoded.as_mut())?;
        }

        // Allocate space for the deserialized elements
        let mut res_affine = vec![ENC::Affine::zero(); size];

        let mut chunk_size = res.len() / num_cpus::get();
        if chunk_size == 0 {
            chunk_size = 1;
        }

        // If any of our threads encounter a deserialization/IO error, catch
        // it with this.
        let decoding_error = Arc::new(Mutex::new(None));

        crossbeam::scope(|scope| {
            for (source, target) in res
                .chunks(chunk_size)
                .zip(res_affine.chunks_mut(chunk_size))
            {
                let decoding_error = decoding_error.clone();

                scope.spawn(move || {
                    assert_eq!(source.len(), target.len());
                    for (source, target) in source.iter().zip(target.iter_mut()) {
                        match {
                            // If we're a participant, we don't need to check all of the
                            // elements in the accumulator, which saves a lot of time.
                            // The hash chain prevents this from being a problem: the
                            // transcript guarantees that the accumulator was properly
                            // formed.
                            match checked {
                                CheckForCorrectness::Yes => {
                                    // Points at infinity are never expected in the accumulator
                                    source
                                        .into_affine()
                                        .map_err(|e| e.into())
                                        .and_then(|source| {
                                            if source.is_zero() {
                                                Err(DeserializationError::PointAtInfinity)
                                            } else {
                                                Ok(source)
                                            }
                                        })
                                }
                                CheckForCorrectness::No => {
                                    source.into_affine_unchecked().map_err(|e| e.into())
                                }
                            }
                        } {
                            Ok(source) => {
                                *target = source;
                            }
                            Err(e) => {
                                *decoding_error.lock().unwrap() = Some(e);
                            }
                        }
                    }
                });
            }
        });

        // extra check that during the decompression all the the initially initialized infinitu points
        // were replaced with something
        for decoded in res_affine.iter() {
            if decoded.is_zero() {
                return Err(DeserializationError::PointAtInfinity);
            }
        }

        match Arc::try_unwrap(decoding_error)
            .unwrap()
            .into_inner()
            .unwrap()
        {
            Some(e) => Err(e),
            None => Ok(res_affine),
        }
    }

    fn write_all(
        &mut self,
        chunk_start: usize,
        compression: UseCompression,
        element_type: ElementType,
        output: &mut [u8],
    ) -> io::Result<()> {
        match element_type {
            ElementType::TauG1 => {
                for (i, c) in self.tau_powers_g1.clone().iter().enumerate() {
                    let index = chunk_start + i;
                    self.write_point(index, c, compression, element_type.clone(), output)?;
                }
            }
            ElementType::TauG2 => {
                for (i, c) in self.tau_powers_g2.clone().iter().enumerate() {
                    let index = chunk_start + i;
                    self.write_point(index, c, compression, element_type.clone(), output)?;
                }
            }
            ElementType::AlphaG1 => {
                for (i, c) in self.alpha_tau_powers_g1.clone().iter().enumerate() {
                    let index = chunk_start + i;
                    self.write_point(index, c, compression, element_type.clone(), output)?;
                }
            }
            ElementType::BetaG1 => {
                for (i, c) in self.beta_tau_powers_g1.clone().iter().enumerate() {
                    let index = chunk_start + i;
                    self.write_point(index, c, compression, element_type.clone(), output)?;
                }
            }
            ElementType::BetaG2 => {
                let index = chunk_start;
                self.write_point(
                    index,
                    &self.beta_g2.clone(),
                    compression,
                    element_type.clone(),
                    output,
                )?
            }
        };

        Ok(())
    }

    fn write_point<C>(
        &mut self,
        index: usize,
        p: &C,
        compression: UseCompression,
        element_type: ElementType,
        output: &mut [u8],
    ) -> io::Result<()>
    where
        C: CurveAffine<Engine = E, Scalar = E::Fr>,
    {
        let output = output.as_mut();
        match element_type {
            ElementType::TauG1 => {
                if index >= self.parameters.powers_g1_length {
                    return Ok(());
                }
            }
            ElementType::AlphaG1
            | ElementType::BetaG1
            | ElementType::BetaG2
            | ElementType::TauG2 => {
                if index >= self.parameters.powers_length {
                    return Ok(());
                }
            }
        };

        match compression {
            UseCompression::Yes => {
                let position = self.calculate_position(index, element_type, compression);
                // let size = self.get_size(element_type, compression);
                (&mut output[position..]).write_all(p.into_compressed().as_ref())?;
            }
            UseCompression::No => {
                let position = self.calculate_position(index, element_type, compression);
                // let size = self.get_size(element_type, compression);
                (&mut output[position..]).write_all(p.into_uncompressed().as_ref())?;
            }
        };

        Ok(())
    }

    /// Write the accumulator with some compression behavior.
    pub fn write_chunk(
        &mut self,
        chunk_start: usize,
        compression: UseCompression,
        output: &mut [u8],
    ) -> io::Result<()> {
        self.write_all(chunk_start, compression, ElementType::TauG1, output)?;
        if chunk_start < self.parameters.powers_length {
            self.write_all(chunk_start, compression, ElementType::TauG2, output)?;
            self.write_all(chunk_start, compression, ElementType::AlphaG1, output)?;
            self.write_all(chunk_start, compression, ElementType::BetaG1, output)?;
            self.write_all(chunk_start, compression, ElementType::BetaG2, output)?;
        }

        Ok(())
    }

    /// Transforms the accumulator with a private key.
    /// Due to large amount of data in a previous accumulator even in the compressed form
    /// this function can now work on compressed input. Output can be made in any form
    /// WARNING: Contributor does not have to check that values from challenge file were serialized
    /// correctly, but we may want to enforce it if a ceremony coordinator does not recompress the previous
    /// contribution into the new challenge file
    pub fn transform(
        input: &[u8],
        output: &mut [u8],
        input_is_compressed: UseCompression,
        compress_the_output: UseCompression,
        check_input_for_correctness: CheckForCorrectness,
        key: &PrivateKey<E>,
        parameters: &'a CeremonyParams<E>,
    ) -> io::Result<()> {
        /// Exponentiate a large number of points, with an optional coefficient to be applied to the
        /// exponent.
        fn batch_exp<EE: Engine, C: CurveAffine<Engine = EE, Scalar = EE::Fr>>(
            bases: &mut [C],
            exp: &[C::Scalar],
            coeff: Option<&C::Scalar>,
        ) {
            assert_eq!(bases.len(), exp.len());
            let mut projective = vec![C::Projective::zero(); bases.len()];
            let chunk_size = bases.len() / num_cpus::get();

            // Perform wNAF over multiple cores, placing results into `projective`.
            crossbeam::scope(|scope| {
                for ((bases, exp), projective) in bases
                    .chunks_mut(chunk_size)
                    .zip(exp.chunks(chunk_size))
                    .zip(projective.chunks_mut(chunk_size))
                {
                    scope.spawn(move || {
                        let mut wnaf = Wnaf::new();

                        for ((base, exp), projective) in
                            bases.iter_mut().zip(exp.iter()).zip(projective.iter_mut())
                        {
                            let mut exp = *exp;
                            if let Some(coeff) = coeff {
                                exp.mul_assign(coeff);
                            }

                            *projective =
                                wnaf.base(base.into_projective(), 1).scalar(exp.into_repr());
                        }
                    });
                }
            });

            // Perform batch normalization
            crossbeam::scope(|scope| {
                for projective in projective.chunks_mut(chunk_size) {
                    scope.spawn(move || {
                        C::Projective::batch_normalization(projective);
                    });
                }
            });

            // Turn it all back into affine points
            for (projective, affine) in projective.iter().zip(bases.iter_mut()) {
                *affine = projective.into_affine();
                assert!(
                    !affine.is_zero(),
                    "your contribution happened to produce a point at infinity, please re-run"
                );
            }
        }

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

                batch_exp::<E, _>(&mut accumulator.tau_powers_g1, &taupowers[0..], None);
                batch_exp::<E, _>(&mut accumulator.tau_powers_g2, &taupowers[0..], None);
                batch_exp::<E, _>(
                    &mut accumulator.alpha_tau_powers_g1,
                    &taupowers[0..],
                    Some(&key.alpha),
                );
                batch_exp::<E, _>(
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

                batch_exp::<E, _>(&mut accumulator.tau_powers_g1, &taupowers[0..], None);
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
    ) -> io::Result<()> {
        // Write the first Tau powers in chunks where every initial element is a G1 or G2 `one`
        for chunk in &(0..parameters.powers_length).chunks(parameters.batch_size) {
            if let MinMax(start, end) = chunk.minmax() {
                let size = end - start + 1;
                let mut accumulator = Self {
                    tau_powers_g1: vec![E::G1Affine::one(); size],
                    tau_powers_g2: vec![E::G2Affine::one(); size],
                    alpha_tau_powers_g1: vec![E::G1Affine::one(); size],
                    beta_tau_powers_g1: vec![E::G1Affine::one(); size],
                    beta_g2: E::G2Affine::one(),
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
                let mut accumulator = Self {
                    tau_powers_g1: vec![E::G1Affine::one(); size],
                    tau_powers_g2: vec![],
                    alpha_tau_powers_g1: vec![],
                    beta_tau_powers_g1: vec![],
                    beta_g2: E::G2Affine::one(),
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

/// Verifies a transformation of the `BatchedAccumulator` with the `PublicKey`, given a 64-byte transcript `digest`.
pub fn verify_transform<E: Engine>(
    before: &BatchedAccumulator<E>,
    after: &BatchedAccumulator<E>,
    key: &PublicKey<E>,
    digest: &[u8],
) -> bool {
    assert_eq!(digest.len(), 64);

    let tau_g2_s = compute_g2_s::<E>(&digest, &key.tau_g1.0, &key.tau_g1.1, 0);
    let alpha_g2_s = compute_g2_s::<E>(&digest, &key.alpha_g1.0, &key.alpha_g1.1, 1);
    let beta_g2_s = compute_g2_s::<E>(&digest, &key.beta_g1.0, &key.beta_g1.1, 2);

    // Check the proofs-of-knowledge for tau/alpha/beta

    // g1^s / g1^(s*x) = g2^s / g2^(s*x)
    if !same_ratio(key.tau_g1, (tau_g2_s, key.tau_g2)) {
        return false;
    }
    if !same_ratio(key.alpha_g1, (alpha_g2_s, key.alpha_g2)) {
        return false;
    }
    if !same_ratio(key.beta_g1, (beta_g2_s, key.beta_g2)) {
        return false;
    }

    // Check the correctness of the generators for tau powers
    if after.tau_powers_g1[0] != E::G1Affine::one() {
        return false;
    }
    if after.tau_powers_g2[0] != E::G2Affine::one() {
        return false;
    }

    // Did the participant multiply the previous tau by the new one?
    if !same_ratio(
        (before.tau_powers_g1[1], after.tau_powers_g1[1]),
        (tau_g2_s, key.tau_g2),
    ) {
        return false;
    }

    // Did the participant multiply the previous alpha by the new one?
    if !same_ratio(
        (before.alpha_tau_powers_g1[0], after.alpha_tau_powers_g1[0]),
        (alpha_g2_s, key.alpha_g2),
    ) {
        return false;
    }

    // Did the participant multiply the previous beta by the new one?
    if !same_ratio(
        (before.beta_tau_powers_g1[0], after.beta_tau_powers_g1[0]),
        (beta_g2_s, key.beta_g2),
    ) {
        return false;
    }
    if !same_ratio(
        (before.beta_tau_powers_g1[0], after.beta_tau_powers_g1[0]),
        (before.beta_g2, after.beta_g2),
    ) {
        return false;
    }

    // Are the powers of tau correct?
    if !same_ratio(
        power_pairs(&after.tau_powers_g1),
        (after.tau_powers_g2[0], after.tau_powers_g2[1]),
    ) {
        return false;
    }
    if !same_ratio(
        power_pairs(&after.tau_powers_g2),
        (after.tau_powers_g1[0], after.tau_powers_g1[1]),
    ) {
        return false;
    }
    if !same_ratio(
        power_pairs(&after.alpha_tau_powers_g1),
        (after.tau_powers_g2[0], after.tau_powers_g2[1]),
    ) {
        return false;
    }
    if !same_ratio(
        power_pairs(&after.beta_tau_powers_g1),
        (after.tau_powers_g2[0], after.tau_powers_g2[1]),
    ) {
        return false;
    }

    true
}
