use generic_array::GenericArray;
/// Memory constrained accumulator that checks parts of the initial information in parts that fit to memory
/// and then contributes to entropy in parts as well
use log::info;
use typenum::consts::U64;
use zexe_algebra::PairingEngine as Engine;

use super::{
    keypair::{PrivateKey, PublicKey},
    parameters::{CeremonyParams, CheckForCorrectness, UseCompression},
    raw::raw_accumulator,
    utils::{blank_hash, Result},
};
/// The `BatchedAccumulator` is an object that participants of the ceremony contribute
/// randomness to. This object contains powers of trapdoor `tau` in G1 and in G2 over
/// fixed generators, and additionally in G1 over two other generators of exponents
/// `alpha` and `beta` over those fixed generators. In other words:
///
/// * (τ, τ<sup>2</sup>, ..., τ<sup>2<sup>22</sup> - 2</sup>, α, ατ, ατ<sup>2</sup>, ..., ατ<sup>2<sup>21</sup> - 1</sup>, β, βτ, βτ<sup>2</sup>, ..., βτ<sup>2<sup>21</sup> - 1</sup>)<sub>1</sub>
/// * (β, τ, τ<sup>2</sup>, ..., τ<sup>2<sup>21</sup> - 1</sup>)<sub>2</sub>
#[derive(Debug)]
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

impl<'a, E: Engine> PartialEq for BatchedAccumulator<'a, E> {
    fn eq(&self, other: &Self) -> bool {
        self.tau_powers_g1 == other.tau_powers_g1
            && self.tau_powers_g2 == other.tau_powers_g2
            && self.alpha_tau_powers_g1 == other.alpha_tau_powers_g1
            && self.beta_tau_powers_g1 == other.beta_tau_powers_g1
            && self.hash == other.hash
            && self.beta_g2 == other.beta_g2
    }
}

impl<'a, E: Engine + Sync> BatchedAccumulator<'a, E> {
    /// Generates the initial accumulator
    pub fn generate_initial(
        output: &mut [u8],
        compress_the_output: UseCompression,
        parameters: &'a CeremonyParams<E>,
    ) -> Result<()> {
        raw_accumulator::init(output, parameters, compress_the_output);
        Ok(())
    }

    pub fn contribute(
        input: &[u8],
        output: &mut [u8],
        input_is_compressed: UseCompression,
        compress_the_output: UseCompression,
        _check_input_for_correctness: CheckForCorrectness,
        key: &PrivateKey<E>,
        parameters: &'a CeremonyParams<E>,
    ) -> Result<()> {
        raw_accumulator::contribute(
            (input, input_is_compressed),
            (output, compress_the_output),
            key,
            parameters,
        )?;
        info!("Contributed to the accumulator!");
        Ok(())
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
        _check_input_for_correctness: CheckForCorrectness,
        _check_output_for_correctness: CheckForCorrectness,
        parameters: &'a CeremonyParams<E>,
    ) -> Result<()> {
        raw_accumulator::verify(
            (input, input_is_compressed),
            (output, output_is_compressed),
            key,
            digest,
            parameters,
        )?;
        Ok(())
    }

    pub fn serialize(
        &self,
        output: &mut [u8],
        compression: UseCompression,
        parameters: &'a CeremonyParams<E>,
    ) -> Result<()> {
        let elements = (
            self.tau_powers_g1.as_ref(),
            self.tau_powers_g2.as_ref(),
            self.alpha_tau_powers_g1.as_ref(),
            self.beta_tau_powers_g1.as_ref(),
            &self.beta_g2,
        );

        raw_accumulator::serialize(elements, output, compression, parameters)?;

        Ok(())
    }

    pub fn deserialize(
        input: &[u8],
        _check_input_for_correctness: CheckForCorrectness,
        compression: UseCompression,
        parameters: &'a CeremonyParams<E>,
    ) -> Result<BatchedAccumulator<'a, E>> {
        let (tau_powers_g1, tau_powers_g2, alpha_tau_powers_g1, beta_tau_powers_g1, beta_g2) =
            raw_accumulator::deserialize(input, compression, parameters)?;
        Ok(BatchedAccumulator {
            tau_powers_g1,
            tau_powers_g2,
            alpha_tau_powers_g1,
            beta_tau_powers_g1,
            beta_g2,
            hash: blank_hash(),
            parameters,
        })
    }

    pub fn decompress(
        input: &[u8],
        output: &mut [u8],
        _check_input_for_correctness: CheckForCorrectness,
        parameters: &'a CeremonyParams<E>,
    ) -> Result<()> {
        raw_accumulator::decompress(input, output, parameters)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::{
        batch_exp, calculate_hash, generate_powers_of_tau,
        test_helpers::{random_point, random_point_vec},
    };
    use rand::thread_rng;
    use zexe_algebra::curves::{
        bls12_377::Bls12_377, bls12_381::Bls12_381, sw6::SW6, AffineCurve, ProjectiveCurve,
    };

    #[test]
    fn serialize_multiple_batches() {
        // this test ensures that we can serialize for batches which are smaller, equal
        // or _bigger_ than any of the G1/G2 vector sizes
        for batch in 1..10 {
            serialize_accumulator_curve::<Bls12_377>(UseCompression::Yes, 2, batch);
        }
    }

    #[test]
    fn serializer_bls12_381() {
        serialize_accumulator_curve::<Bls12_381>(UseCompression::Yes, 2, 2);
        serialize_accumulator_curve::<Bls12_381>(UseCompression::No, 2, 2);
    }

    #[test]
    fn serializer_bls12_377() {
        serialize_accumulator_curve::<Bls12_377>(UseCompression::Yes, 2, 2);
        serialize_accumulator_curve::<Bls12_377>(UseCompression::No, 2, 2);
    }

    #[test]
    #[ignore] // this takes very long to run
    fn serializer_sw6() {
        serialize_accumulator_curve::<SW6>(UseCompression::Yes, 2, 2);
        serialize_accumulator_curve::<SW6>(UseCompression::No, 2, 2);
    }

    #[test]
    fn generate_initial_test() {
        generate_initial_test_curve::<Bls12_377>(4, 4, UseCompression::Yes);
        generate_initial_test_curve::<Bls12_377>(4, 4, UseCompression::No);
    }

    #[test]
    fn test_contribute() {
        // receive a compressed/uncompressed input, contribute to it and produce
        // a compressed/decompressed output
        test_contribute_curve::<Bls12_377>(2, 2, UseCompression::Yes, UseCompression::Yes);
        test_contribute_curve::<Bls12_377>(2, 2, UseCompression::No, UseCompression::Yes);
        test_contribute_curve::<Bls12_377>(2, 2, UseCompression::Yes, UseCompression::No);
        test_contribute_curve::<Bls12_377>(3, 4, UseCompression::No, UseCompression::No);
        test_contribute_curve::<Bls12_377>(6, 64, UseCompression::No, UseCompression::No);
        // works even if the batch is larger than the powers
        test_contribute_curve::<Bls12_377>(6, 128, UseCompression::No, UseCompression::Yes);
    }

    fn test_contribute_curve<E: Engine>(
        powers: usize,
        batch: usize,
        compressed_input: UseCompression,
        compressed_output: UseCompression,
    ) {
        let parameters = CeremonyParams::<E>::new(powers, batch);
        let expected_response_length = parameters.get_length(compressed_output);

        // get a non-mutable copy of the initial accumulator state
        let (input, mut before) = generate_input(&parameters, compressed_input);

        let mut output = vec![0; expected_response_length];
        // Construct our keypair using the RNG we created above
        let current_accumulator_hash = blank_hash();
        let mut rng = thread_rng();
        let (_, privkey) = crate::keypair::keypair(&mut rng, current_accumulator_hash.as_ref())
            .expect("could not generate keypair");

        BatchedAccumulator::contribute(
            &input,
            &mut output,
            compressed_input,
            compressed_output,
            CheckForCorrectness::Yes,
            &privkey,
            &parameters,
        )
        .unwrap();

        let deserialized = BatchedAccumulator::deserialize(
            &output,
            CheckForCorrectness::Yes,
            compressed_output,
            &parameters,
        )
        .unwrap();

        let taupowers = generate_powers_of_tau::<E>(&privkey.tau, 0, parameters.powers_g1_length);
        batch_exp(
            &mut before.tau_powers_g1,
            &taupowers[0..parameters.powers_g1_length],
            None,
        )
        .unwrap();
        batch_exp(
            &mut before.tau_powers_g2,
            &taupowers[0..parameters.powers_length],
            None,
        )
        .unwrap();
        batch_exp(
            &mut before.alpha_tau_powers_g1,
            &taupowers[0..parameters.powers_length],
            Some(&privkey.alpha),
        )
        .unwrap();
        batch_exp(
            &mut before.beta_tau_powers_g1,
            &taupowers[0..parameters.powers_length],
            Some(&privkey.beta),
        )
        .unwrap();
        before.beta_g2 = before.beta_g2.mul(privkey.beta).into_affine();

        assert_eq!(deserialized, before);
    }

    #[test]
    fn test_verify_transformation() {
        test_verify_transformation_curve::<Bls12_377>(
            2,
            2,
            UseCompression::Yes,
            UseCompression::Yes,
        );
        test_verify_transformation_curve::<Bls12_377>(2, 2, UseCompression::No, UseCompression::No);
        test_verify_transformation_curve::<Bls12_377>(
            2,
            2,
            UseCompression::Yes,
            UseCompression::No,
        );
        test_verify_transformation_curve::<Bls12_381>(
            2,
            2,
            UseCompression::No,
            UseCompression::Yes,
        );
    }

    fn test_verify_transformation_curve<E: Engine>(
        powers: usize,
        batch: usize,
        compressed_input: UseCompression,
        compressed_output: UseCompression,
    ) {
        let parameters = CeremonyParams::<E>::new(powers, batch);
        let correctness = CheckForCorrectness::Yes;

        // allocate the input/output vectors
        let (input, _) = generate_input(&parameters, compressed_input);
        let mut output = generate_output(&parameters, compressed_output);

        // Construct our keypair
        let current_accumulator_hash = blank_hash();
        let mut rng = thread_rng();
        let (pubkey, privkey) =
            crate::keypair::keypair(&mut rng, current_accumulator_hash.as_ref())
                .expect("could not generate keypair");

        // transform the accumulator
        BatchedAccumulator::contribute(
            &input,
            &mut output,
            compressed_input,
            compressed_output,
            CheckForCorrectness::Yes,
            &privkey,
            &parameters,
        )
        .unwrap();
        // ensure that the key is not available to the verifier
        drop(privkey);

        let res = BatchedAccumulator::verify_transformation(
            &input,
            &output,
            &pubkey,
            &current_accumulator_hash,
            compressed_input,
            compressed_output,
            correctness,
            correctness,
            &parameters,
        );
        assert!(res.is_ok());

        // subsequent participants must use the hash of the accumulator they received
        let current_accumulator_hash = calculate_hash(&output);

        let (pubkey, privkey) =
            crate::keypair::keypair(&mut rng, current_accumulator_hash.as_ref())
                .expect("could not generate keypair");

        // generate a new output vector for the 2nd participant's contribution
        let mut output_2 = generate_output(&parameters, compressed_output);
        // we use the first output as input
        BatchedAccumulator::contribute(
            &output,
            &mut output_2,
            compressed_output,
            compressed_output,
            CheckForCorrectness::Yes,
            &privkey,
            &parameters,
        )
        .unwrap();
        // ensure that the key is not available to the verifier
        drop(privkey);

        let res = BatchedAccumulator::verify_transformation(
            &output,
            &output_2,
            &pubkey,
            &current_accumulator_hash,
            compressed_output,
            compressed_output,
            correctness,
            correctness,
            &parameters,
        );
        assert!(res.is_ok());

        // verification will fail if the old hash is used
        let res = BatchedAccumulator::verify_transformation(
            &output,
            &output_2,
            &pubkey,
            &blank_hash(),
            compressed_output,
            compressed_output,
            correctness,
            correctness,
            &parameters,
        );
        assert!(res.is_err());

        // verification will fail if even 1 byte is modified
        output_2[100] = 0;
        let res = BatchedAccumulator::verify_transformation(
            &output,
            &output_2,
            &pubkey,
            &current_accumulator_hash,
            compressed_output,
            compressed_output,
            correctness,
            correctness,
            &parameters,
        );
        assert!(res.is_err());
    }

    #[test]
    fn test_decompress() {
        test_decompress_curve::<Bls12_377>()
    }

    fn test_decompress_curve<E: Engine>() {
        let parameters = CeremonyParams::<E>::new(2, 2);
        // generate a random input compressed accumulator
        let (input, before) = generate_random_accumulator(&parameters, UseCompression::Yes);
        let mut output = generate_output(&parameters, UseCompression::No);

        // decompress the input to the output
        BatchedAccumulator::decompress(&input, &mut output, CheckForCorrectness::Yes, &parameters)
            .unwrap();

        // deserializes the decompressed output
        let deserialized = BatchedAccumulator::deserialize(
            &output,
            CheckForCorrectness::Yes,
            UseCompression::No,
            &parameters,
        )
        .unwrap();
        assert_eq!(deserialized, before);

        // trying to deserialize it as compressed should obviously fail
        BatchedAccumulator::deserialize(
            &output,
            CheckForCorrectness::Yes,
            UseCompression::Yes,
            &parameters,
        )
        .unwrap_err();
    }

    fn generate_initial_test_curve<E: Engine>(
        powers: usize,
        batch: usize,
        compression: UseCompression,
    ) {
        let parameters = CeremonyParams::<E>::new(powers, batch);
        let expected_challenge_length = match compression {
            UseCompression::Yes => parameters.contribution_size - parameters.public_key_size,
            UseCompression::No => parameters.accumulator_size,
        };

        let mut output = vec![0; expected_challenge_length];
        BatchedAccumulator::generate_initial(&mut output, compression, &parameters).unwrap();

        let deserialized = BatchedAccumulator::deserialize(
            &output,
            CheckForCorrectness::Yes,
            compression,
            &parameters,
        )
        .unwrap();

        let g1_zero = E::G1Affine::prime_subgroup_generator();
        let g2_zero = E::G2Affine::prime_subgroup_generator();

        assert_eq!(
            deserialized.tau_powers_g1,
            vec![g1_zero; parameters.powers_g1_length]
        );
        assert_eq!(
            deserialized.tau_powers_g2,
            vec![g2_zero; parameters.powers_length]
        );
        assert_eq!(
            deserialized.alpha_tau_powers_g1,
            vec![g1_zero; parameters.powers_length]
        );
        assert_eq!(
            deserialized.beta_tau_powers_g1,
            vec![g1_zero; parameters.powers_length]
        );
        assert_eq!(deserialized.beta_g2, g2_zero);
    }

    fn serialize_accumulator_curve<E: Engine + Sync>(
        compress: UseCompression,
        size: usize,
        batch: usize,
    ) {
        // create a small accumulator with some random state
        let parameters = CeremonyParams::<E>::new(size, batch);
        let (buffer, accumulator) = generate_random_accumulator(&parameters, compress);
        let deserialized = BatchedAccumulator::deserialize(
            &buffer,
            CheckForCorrectness::Yes,
            compress,
            &parameters,
        )
        .unwrap();
        assert_eq!(deserialized, accumulator);
    }

    // Helpers
    fn generate_random_accumulator<'a, E: Engine>(
        parameters: &'a CeremonyParams<E>,
        compressed: UseCompression,
    ) -> (Vec<u8>, BatchedAccumulator<'a, E>) {
        let tau_g1_size = parameters.powers_g1_length;
        let other_size = parameters.powers_length;
        let rng = &mut thread_rng();
        let acc = BatchedAccumulator {
            tau_powers_g1: random_point_vec(tau_g1_size, rng),
            tau_powers_g2: random_point_vec(other_size, rng),
            alpha_tau_powers_g1: random_point_vec(other_size, rng),
            beta_tau_powers_g1: random_point_vec(other_size, rng),
            beta_g2: random_point(rng),
            hash: blank_hash(),
            parameters,
        };
        let len = parameters.get_length(compressed);
        let mut buf = vec![0; len];
        acc.serialize(&mut buf, compressed, parameters).unwrap();
        (buf, acc)
    }

    fn generate_input<E: Engine>(
        parameters: &CeremonyParams<E>,
        compressed: UseCompression,
    ) -> (Vec<u8>, BatchedAccumulator<E>) {
        let len = parameters.get_length(compressed);
        let mut output = vec![0; len];
        BatchedAccumulator::generate_initial(&mut output, compressed, &parameters).unwrap();
        let mut input = vec![0; len];
        input.copy_from_slice(&output);
        let before = BatchedAccumulator::deserialize(
            &output,
            CheckForCorrectness::Yes,
            compressed,
            &parameters,
        )
        .unwrap();
        (input, before)
    }

    fn generate_output<E: Engine>(
        parameters: &CeremonyParams<E>,
        compressed: UseCompression,
    ) -> Vec<u8> {
        let expected_response_length = parameters.get_length(compressed);
        vec![0; expected_response_length]
    }
}
