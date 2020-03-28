use phase2::parameters::MPCParameters;
use powersoftau::{parameters::CeremonyParams, BatchedAccumulator};
use snark_utils::{Groth16Params, UseCompression};
use test_helpers::{setup_verify, TestCircuit};

use rand::{thread_rng, Rng};
use zexe_algebra::{Bls12_377, Bls12_381, PairingEngine, SW6};
use zexe_groth16::{create_random_proof, prepare_verifying_key, verify_proof, Parameters};
use zexe_r1cs_core::ConstraintSynthesizer;

fn generate_mpc_parameters<E, C>(c: C, rng: &mut impl Rng) -> MPCParameters<E>
where
    E: PairingEngine,
    C: Clone + ConstraintSynthesizer<E::Fr>,
{
    let powers = 6; // powers of tau
    let batch = 4;
    let params = CeremonyParams::<E>::new(powers, batch);
    let compressed = UseCompression::Yes;
    // make 1 power of tau contribution (assume powers of tau gets calculated properly)
    let (_, output, _, _) = setup_verify(compressed, compressed, &params);
    let accumulator = BatchedAccumulator::deserialize(&output, compressed, &params).unwrap();

    // prepare only the first 32 powers (for whatever reason)
    let groth_params = Groth16Params::<E>::new(
        32,
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

    // perform the MPC on only the amount of constraints required for the circuit
    let mut counter = zexe_r1cs_std::test_constraint_counter::ConstraintCounter::new();
    c.clone().generate_constraints(&mut counter).unwrap();
    let phase2_size = counter.num_aux + counter.num_inputs + counter.num_constraints;

    let mut mpc =
        MPCParameters::<E>::new_from_buffer(c, writer.as_mut(), compressed, 32, phase2_size)
            .unwrap();

    let before = mpc.clone();
    // it is _not_ safe to use it yet, there must be 1 contribution
    mpc.contribute(rng).unwrap();

    before.verify(&mpc).unwrap();

    mpc
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
#[ignore]
fn test_groth_sw6() {
    groth_test_curve::<SW6>()
}

fn groth_test_curve<E: PairingEngine>() {
    let rng = &mut thread_rng();
    // generate the params
    let params: Parameters<E> = {
        let c = TestCircuit::<E>(None);
        let setup = generate_mpc_parameters(c, rng);
        setup.get_params().clone()
    };

    // Prepare the verification key (for proof verification)
    let pvk = prepare_verifying_key(&params.vk);

    // Create a proof with these params
    let proof = {
        let c = TestCircuit::<E>(Some(E::Fr::from(5)));
        create_random_proof(c, &params, rng).unwrap()
    };

    let res = verify_proof(&pvk, &proof, &[E::Fr::from(25)]);
    assert!(res.is_ok());
}
