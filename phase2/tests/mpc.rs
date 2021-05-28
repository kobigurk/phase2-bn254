use algebra::{Bls12_377, Bls12_381, PairingEngine, PrimeField, BW6_761};
use groth16::{create_random_proof, prepare_verifying_key, verify_proof, Parameters};
use phase1::{
    helpers::testing::{setup_verify, CheckForCorrectness},
    parameters::Phase1Parameters,
    Phase1, ProvingSystem,
};
use phase2::load_circuit::Matrices;
use phase2::parameters::circuit_to_qap;
use phase2::{
    chunked_groth16::verify,
    helpers::testing::TestCircuit,
    parameters::{MPCParameters, Phase2ContributionMode},
};
use r1cs_core::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};
use rand::{thread_rng, Rng};
use setup_utils::{derive_rng_from_seed, BatchExpMode, Groth16Params, UseCompression};

fn generate_mpc_parameters<E, C>(c: C, rng: &mut impl Rng) -> MPCParameters<E>
where
    E: PairingEngine,
    C: Clone + ConstraintSynthesizer<E::Fr>,
{
    // perform the MPC on only the amount of constraints required for the circuit
    let counter = ConstraintSystem::new_ref();
    counter.set_mode(SynthesisMode::Setup);
    c.clone().generate_constraints(counter.clone()).unwrap();

    let phase2_size = std::cmp::max(
        counter.num_constraints() + counter.num_instance_variables(),
        counter.num_witness_variables() + counter.num_instance_variables(),
    )
    .next_power_of_two();
    let powers = (phase2_size as u64).trailing_zeros() as usize;

    let batch = 4;
    let params = Phase1Parameters::<E>::new_full(ProvingSystem::Groth16, powers, batch);
    let compressed = UseCompression::Yes;

    // make 1 power of tau contribution (assume powers of tau gets calculated properly)
    let (_, output, _, _) = setup_verify(
        compressed,
        CheckForCorrectness::Full,
        compressed,
        BatchExpMode::Auto,
        &params,
    );
    let accumulator = Phase1::deserialize(&output, compressed, CheckForCorrectness::Full, &params).unwrap();

    // prepare only the first 32 powers (for whatever reason)
    let groth_params = Groth16Params::<E>::new(
        1 << powers,
        accumulator.tau_powers_g1,
        accumulator.tau_powers_g2,
        accumulator.alpha_tau_powers_g1,
        accumulator.beta_tau_powers_g1,
        accumulator.beta_g2,
    )
    .unwrap();

    // write the transcript to a file
    let mut writer = vec![];
    groth_params.write(&mut writer, compressed).unwrap();

    let m = circuit_to_qap::<E, C>(c.clone()).unwrap();

    let m = m.to_matrices().unwrap();
    let matrices = Matrices {
        num_instance_variables: m.num_instance_variables,
        num_witness_variables: m.num_witness_variables,
        num_constraints: m.num_constraints,
        a_num_non_zero: m.a_num_non_zero,
        b_num_non_zero: m.b_num_non_zero,
        c_num_non_zero: m.c_num_non_zero,
        a: m.a,
        b: m.b,
        c: m.c,
    };

    let mut mpc = MPCParameters::<E>::new_from_buffer(
        matrices,
        writer.as_mut(),
        compressed,
        CheckForCorrectness::Full,
        1 << powers,
        phase2_size,
    )
    .unwrap();

    let before = mpc.clone();
    // it is _not_ safe to use it yet, there must be 1 contribution
    mpc.contribute(BatchExpMode::Auto, rng).unwrap();

    before.verify(&mpc).unwrap();

    mpc
}

fn generate_mpc_parameters_chunked<E, C>(c: C) -> MPCParameters<E>
where
    E: PairingEngine,
    C: Clone + ConstraintSynthesizer<E::Fr>,
{
    // perform the MPC on only the amount of constraints required for the circuit
    let counter = ConstraintSystem::new_ref();
    counter.set_mode(SynthesisMode::Setup);
    c.clone().generate_constraints(counter.clone()).unwrap();
    let phase2_size = std::cmp::max(
        counter.num_constraints() + counter.num_instance_variables(),
        counter.num_witness_variables() + counter.num_instance_variables(),
    )
    .next_power_of_two();
    let powers = (phase2_size as u64).trailing_zeros() as usize;

    let batch = 4;
    let params = Phase1Parameters::<E>::new_full(ProvingSystem::Groth16, powers, batch);
    let compressed = UseCompression::Yes;

    // make 1 power of tau contribution (assume powers of tau gets calculated properly)
    let (_, output, _, _) = setup_verify(
        compressed,
        CheckForCorrectness::Full,
        compressed,
        BatchExpMode::Auto,
        &params,
    );
    let accumulator = Phase1::deserialize(&output, compressed, CheckForCorrectness::Full, &params).unwrap();

    // prepare only the first 32 powers (for whatever reason)
    let groth_params = Groth16Params::<E>::new(
        1 << powers,
        accumulator.tau_powers_g1,
        accumulator.tau_powers_g2,
        accumulator.alpha_tau_powers_g1,
        accumulator.beta_tau_powers_g1,
        accumulator.beta_g2,
    )
    .unwrap();
    // write the transcript to a file
    let mut writer = vec![];
    groth_params.write(&mut writer, compressed).unwrap();

    let m = circuit_to_qap::<E, C>(c.clone()).unwrap();

    let m = m.to_matrices().unwrap();
    let matrices = Matrices {
        num_instance_variables: m.num_instance_variables,
        num_witness_variables: m.num_witness_variables,
        num_constraints: m.num_constraints,
        a_num_non_zero: m.a_num_non_zero,
        b_num_non_zero: m.b_num_non_zero,
        c_num_non_zero: m.c_num_non_zero,
        a: m.a,
        b: m.b,
        c: m.c,
    };

    let chunk_size = phase2_size / 3;

    let (full_mpc_before, queries, mut mpcs) = MPCParameters::<E>::new_from_buffer_chunked(
        matrices,
        writer.as_mut(),
        compressed,
        CheckForCorrectness::Full,
        1 << powers,
        phase2_size,
        chunk_size,
    )
    .unwrap();

    let mut full_mpc_before_serialized = vec![];
    full_mpc_before
        .write(&mut full_mpc_before_serialized, UseCompression::Yes)
        .unwrap();

    for mpc in mpcs.iter_mut() {
        let mut rng = derive_rng_from_seed(&[0u8; 32]);
        let before = mpc.clone();
        // it is _not_ safe to use it yet, there must be 1 contribution
        mpc.contribute(BatchExpMode::Auto, &mut rng).unwrap();

        before.verify(&mpc).unwrap();
    }

    let full_mpc_after = MPCParameters::<E>::combine(&queries, &mpcs).unwrap();
    let mut full_mpc_after_serialized = vec![];
    full_mpc_after
        .write(&mut full_mpc_after_serialized, UseCompression::Yes)
        .unwrap();
    verify::<E>(
        &mut full_mpc_before_serialized,
        &mut full_mpc_after_serialized,
        3,
        UseCompression::Yes,
        CheckForCorrectness::Full,
    )
    .unwrap();

    full_mpc_after
}

#[test]
fn test_groth_bls12_377() {
    groth_test_curve::<Bls12_377>()
}

#[test]
fn test_groth_bls12_381() {
    groth_test_curve::<Bls12_381>()
}

#[test]
fn test_groth_bw6() {
    groth_test_curve::<BW6_761>()
}

fn groth_test_curve<E: PairingEngine>() {
    for contribution_mode in &[Phase2ContributionMode::Full, Phase2ContributionMode::Chunked] {
        let rng = &mut thread_rng();
        // generate the params
        let params: Parameters<E> = {
            let c = TestCircuit::<E>(None);
            let setup = match contribution_mode {
                Phase2ContributionMode::Full => generate_mpc_parameters(c, rng),
                Phase2ContributionMode::Chunked => generate_mpc_parameters_chunked(c),
            };
            setup.get_params().clone()
        };

        // Prepare the verification key (for proof verification)
        let pvk = prepare_verifying_key(&params.vk);

        // Create a proof with these params
        let proof = {
            let c = TestCircuit::<E>(Some(<E::Fr as PrimeField>::BigInt::from(5).into()));
            create_random_proof(c, &params, rng).unwrap()
        };

        let res = verify_proof(&pvk, &proof, &[<E::Fr as PrimeField>::BigInt::from(25).into()]);
        assert!(res.unwrap());
    }
}
