#[cfg(test)]
mod test {
    use phase1::{helpers::testing::generate_input, Phase1, Phase1Parameters, ProvingSystem};
    use poly_commit::kzg10::UniversalParams;
    use rand::thread_rng;
    use setup_utils::{blank_hash, BatchExpMode, CheckForCorrectness, UseCompression};

    use algebra::{bls12_377::Fr, Bls12_377, Field, UniformRand};
    use blake2::Blake2s;
    use itertools::Itertools;
    use marlin::Marlin;
    use poly_commit::sonic_pc::SonicKZG10;
    use r1cs_core::{lc, ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use std::{collections::BTreeMap, ops::MulAssign};

    #[derive(Copy, Clone)]
    struct Circuit<F: Field> {
        a: Option<F>,
        b: Option<F>,
        num_constraints: usize,
        num_variables: usize,
    }

    impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for Circuit<ConstraintF> {
        fn generate_constraints(self, cs: ConstraintSystemRef<ConstraintF>) -> Result<(), SynthesisError> {
            let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
            let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
            let c = cs.new_input_variable(|| {
                let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
                let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

                a.mul_assign(&b);
                Ok(a)
            })?;

            for _ in 0..(self.num_variables - 3) {
                let _ = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
            }

            for _ in 0..self.num_constraints {
                cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
            }
            Ok(())
        }
    }

    type MultiPCSonic = SonicKZG10<Bls12_377>;
    type MarlinSonicInst = Marlin<Fr, MultiPCSonic, Blake2s>;

    #[test]
    #[ignore]
    fn test_marlin_sonic_pc() {
        let powers = 16usize;
        let batch = 1usize << 12;
        let parameters = Phase1Parameters::<Bls12_377>::new_full(ProvingSystem::Marlin, powers, batch);
        let expected_response_length = parameters.get_length(UseCompression::No);

        // Get a non-mutable copy of the initial accumulator state.
        let (input, _) = generate_input(&parameters, UseCompression::No, CheckForCorrectness::No);

        let mut output = vec![0; expected_response_length];

        // Construct our keypair using the RNG we created above
        let current_accumulator_hash = blank_hash();
        let mut rng = thread_rng();
        let (_, privkey) =
            Phase1::key_generation(&mut rng, current_accumulator_hash.as_ref()).expect("could not generate keypair");

        Phase1::computation(
            &input,
            &mut output,
            UseCompression::No,
            UseCompression::No,
            CheckForCorrectness::No,
            BatchExpMode::Auto,
            &privkey,
            &parameters,
        )
        .unwrap();

        let deserialized =
            Phase1::deserialize(&output, UseCompression::No, CheckForCorrectness::No, &parameters).unwrap();
        let tau_powers_g1 = deserialized.tau_powers_g1.clone();
        let tau_powers_g2 = deserialized.tau_powers_g2.clone();
        let alpha_powers_g1 = deserialized.alpha_tau_powers_g1.clone();

        let mut alpha_tau_powers_g1 = BTreeMap::new();
        for i in 0..3 {
            alpha_tau_powers_g1.insert(i, alpha_powers_g1[i]);
        }
        alpha_powers_g1[3..]
            .iter()
            .chunks(3)
            .into_iter()
            .enumerate()
            .for_each(|(i, c)| {
                let c = c.into_iter().collect::<Vec<_>>();
                alpha_tau_powers_g1.insert(parameters.powers_length - 1 - (1 << i) + 2, *c[0]);
                alpha_tau_powers_g1.insert(parameters.powers_length - 1 - (1 << i) + 3, *c[1]);
                alpha_tau_powers_g1.insert(parameters.powers_length - 1 - (1 << i) + 4, *c[2]);
            });

        let mut prepared_neg_powers_of_h = BTreeMap::new();
        tau_powers_g2[2..].iter().enumerate().for_each(|(i, p)| {
            prepared_neg_powers_of_h.insert(parameters.powers_length - 1 - (1 << i) + 2, (*p).into());
        });
        let h = tau_powers_g2[0].clone();
        let beta_h = tau_powers_g2[1].clone();
        let universal_params = UniversalParams::<Bls12_377> {
            powers_of_g: tau_powers_g1,
            powers_of_gamma_g: alpha_tau_powers_g1,
            h: h.clone(),
            beta_h: beta_h.clone(),
            prepared_neg_powers_of_h,
            prepared_h: h.into(),
            prepared_beta_h: beta_h.into(),
        };

        for _ in 0..100 {
            let a = Fr::rand(&mut rng);
            let b = Fr::rand(&mut rng);
            let mut c = a;
            c.mul_assign(&b);

            let circ = Circuit {
                a: Some(a),
                b: Some(b),
                num_constraints: 3000,
                num_variables: 2000,
            };

            let (index_pk, index_vk) = MarlinSonicInst::index(&universal_params, circ.clone()).unwrap();
            println!("Called index");

            let proof = MarlinSonicInst::prove(&index_pk, circ, &mut rng).unwrap();
            println!("Called prover");

            assert!(MarlinSonicInst::verify(&index_vk, &[c], &proof, &mut rng).unwrap());
            println!("Called verifier");
            println!("\nShould not verify (i.e. verifier messages should print below):");
            assert!(!MarlinSonicInst::verify(&index_vk, &[a], &proof, &mut rng).unwrap());
        }
    }
}
