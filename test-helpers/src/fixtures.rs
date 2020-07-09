use zexe_algebra::{Field, PairingEngine};
use zexe_r1cs_core::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};

// circuit proving knowledge of a square root
// when generating the Setup, the element inside is None
#[derive(Clone, Debug)]
pub struct TestCircuit<E: PairingEngine>(pub Option<E::Fr>);
impl<E: PairingEngine> ConstraintSynthesizer<E::Fr> for TestCircuit<E> {
    fn generate_constraints<CS: ConstraintSystem<E::Fr>>(
        self,
        cs: &mut CS,
    ) -> std::result::Result<(), SynthesisError> {
        // allocate a private input `x`
        // this can be made public with `alloc_input`, which would then require
        // that the verifier provides it
        let x = cs
            .alloc(|| "x", || self.0.ok_or(SynthesisError::AssignmentMissing))
            .unwrap();
        // 1 input!
        let out = cs
            .alloc_input(
                || "square",
                || {
                    self.0
                        .map(|x| x.square())
                        .ok_or(SynthesisError::AssignmentMissing)
                },
            )
            .unwrap();
        // x * x = x^2
        cs.enforce(|| "x * x = x^2", |lc| lc + x, |lc| lc + x, |lc| lc + out);

        // add some dummy constraints to make the circuit a bit bigger
        // we do this so that we can write a failing test for our MPC
        // where the params are smaller than the circuit size
        // (7 in this case, since we allocated 3 constraints, plus 4 below)
        for _ in 0..4 {
            cs.alloc(
                || "dummy",
                || self.0.ok_or(SynthesisError::AssignmentMissing),
            )
            .unwrap();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zexe_algebra::{Bls12_381, PrimeField};
    use zexe_groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    };

    // no need to run these tests, they're just added as a guideline for how to
    // consume the circuit
    #[test]
    fn test_square_root() {
        test_square_root_curve::<Bls12_381>()
    }

    fn test_square_root_curve<E: PairingEngine>() {
        // This may not be cryptographically safe, use
        // `OsRng` (for example) in production software.
        let rng = &mut rand::thread_rng();
        // Create parameters for our circuit
        let params = {
            let c = TestCircuit::<E>(None);
            generate_random_parameters::<E, _, _>(c, rng).unwrap()
        };
        let pvk = prepare_verifying_key(&params.vk);

        // we know the square root of 25 -> 5
        let out = <E::Fr as PrimeField>::BigInt::from(25u64).into();
        let input = <E::Fr as PrimeField>::BigInt::from(5u64).into();

        // Prover instantiates the circuit and creates a proof
        // with his RNG
        let c = TestCircuit::<E>(Some(input));
        let proof = create_random_proof(c, &params, rng).unwrap();

        // Verifier only needs to know 25 (the output, aka public input),
        // the vk and the proof!
        assert!(verify_proof(&pvk, &proof, &[out]).unwrap());
    }
}
