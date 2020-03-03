use rayon::prelude::*;
use zexe_algebra::{AffineCurve, PairingEngine, ProjectiveCurve, Zero};
use zexe_r1cs_core::Index;

/// Evaluates and returns the provided QAP Polynomial vectors at the provided coefficients.
/// Format: [a_g1, b_g1, b_g2, gamma_abc_g1, l_g1]
/// The returned points are _affine_
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn eval<E: PairingEngine>(
    // Lagrange coefficients for tau
    coeffs_g1: &[E::G1Affine],
    coeffs_g2: &[E::G2Affine],
    alpha_coeffs_g1: &[E::G1Affine],
    beta_coeffs_g1: &[E::G1Affine],
    // QAP polynomials
    at: &[Vec<(E::Fr, Index)>],
    bt: &[Vec<(E::Fr, Index)>],
    ct: &[Vec<(E::Fr, Index)>],
    // The number of inputs
    num_inputs: usize,
) -> (
    Vec<E::G1Affine>,
    Vec<E::G1Affine>,
    Vec<E::G2Affine>,
    Vec<E::G1Affine>,
    Vec<E::G1Affine>,
) {
    // calculate the evaluated polynomials
    let a_g1 = dot_product_vec(at, coeffs_g1, num_inputs);
    let b_g1 = dot_product_vec(bt, coeffs_g1, num_inputs);
    let b_g2 = dot_product_vec(bt, coeffs_g2, num_inputs);
    let ext = dot_product_ext::<E>(
        (at, beta_coeffs_g1),
        (bt, alpha_coeffs_g1),
        (ct, coeffs_g1),
        num_inputs,
    );

    // break to `gamma_abc_g1` and `l` coeffs
    let (gamma_abc_g1, l) = ext.split_at(num_inputs);

    // back to affine and return
    let a_g1 = a_g1.iter().map(|p| p.into_affine()).collect();
    let b_g1 = b_g1.iter().map(|p| p.into_affine()).collect();
    let b_g2 = b_g2.iter().map(|p| p.into_affine()).collect();
    let gamma_abc_g1 = gamma_abc_g1.iter().map(|p| p.into_affine()).collect();
    let l = l.iter().map(|p| p.into_affine()).collect();

    (a_g1, b_g1, b_g2, gamma_abc_g1, l)
}

#[allow(clippy::type_complexity)]
#[allow(clippy::op_ref)] // false positive by clippy
fn dot_product_ext<E: PairingEngine>(
    (at, beta_coeffs_g1): (&[Vec<(E::Fr, Index)>], &[E::G1Affine]),
    (bt, alpha_coeffs_g1): (&[Vec<(E::Fr, Index)>], &[E::G1Affine]),
    (ct, coeffs_g1): (&[Vec<(E::Fr, Index)>], &[E::G1Affine]),
    num_inputs: usize,
) -> Vec<E::G1Projective> {
    let mut ret = at
        .par_iter()
        .zip(bt.par_iter().zip(ct))
        .map(|(at, (bt, ct))| {
            dot_product(&at, &beta_coeffs_g1, num_inputs)
                + &dot_product(&bt, &alpha_coeffs_g1, num_inputs)
                + &dot_product(&ct, &coeffs_g1, num_inputs)
        })
        .collect::<Vec<_>>();
    E::G1Projective::batch_normalization(&mut ret);
    ret
}

/// Returns a batch normalized projective vector where the coefficients
/// have been applied to the input
/// This is a NxN * Nx1 -> Nx1 matrix multiplication basically
fn dot_product_vec<C: AffineCurve>(
    input: &[Vec<(C::ScalarField, Index)>],
    coeffs: &[C],
    num_inputs: usize,
) -> Vec<C::Projective> {
    let mut ret = input
        .par_iter()
        .map(|row| dot_product(row, coeffs, num_inputs))
        .collect::<Vec<_>>();
    // Batch normalize
    C::Projective::batch_normalization(&mut ret);
    ret
}

/// Executes a dot product between two vectors (1xN * Nx1)
/// If the Index of the input is an Auxiliary index it uses the
/// `coeffs` vector offset by `num_inputs`
#[allow(clippy::redundant_closure)]
fn dot_product<C: AffineCurve>(
    input: &[(C::ScalarField, Index)],
    coeffs: &[C],
    num_inputs: usize,
) -> C::Projective {
    input
        .into_par_iter()
        .fold(
            || C::Projective::zero(),
            |mut sum, &(coeff, lag)| {
                let ind = match lag {
                    Index::Input(i) => i,
                    Index::Aux(i) => num_inputs + i,
                };
                sum += &coeffs[ind].mul(coeff);
                sum
            },
        )
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, Rng};
    use test_helpers::random_point_vec;
    use zexe_algebra::{
        bls12_377::{Bls12_377, Fr, G1Affine, G1Projective},
        UniformRand,
    };

    fn gen_input(rng: &mut impl Rng) -> Vec<(Fr, Index)> {
        let scalar = (0..6).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
        vec![
            (scalar[0], Index::Input(0)),
            (scalar[1], Index::Input(1)),
            (scalar[2], Index::Aux(0)),
            (scalar[3], Index::Aux(2)), // can they ever be out of order in reality?
            (scalar[4], Index::Aux(1)),
            (scalar[5], Index::Input(2)),
        ]
    }

    fn get_expected(elements: &[G1Affine], scalar: &[Fr]) -> G1Projective {
        let num_inputs = 3;
        elements[0].mul(scalar[0])
            + elements[1].mul(scalar[1])
            + elements[2].mul(scalar[5])
            // Auxiliary inputs be multiplied with the coeffs
            // offset by the number of inputs
            + elements[num_inputs].mul(scalar[2])
            + elements[num_inputs + 2].mul(scalar[3])
            + elements[num_inputs + 1].mul(scalar[4])
    }

    #[test]
    fn test_dot_product() {
        // 3 inputs, 3 aux
        let mut rng = thread_rng();
        let num_inputs = 3;
        let input = gen_input(&mut rng);
        let scalar = input.iter().map(|i| i.0).collect::<Vec<_>>();
        let elements: Vec<G1Affine> = random_point_vec(6, &mut rng);

        let expected = get_expected(&elements, &scalar);

        let got = dot_product(&input, &elements, num_inputs);

        assert_eq!(got, expected);

        // it also applies the coefficients vector to each row
        // in the inputs vector
        let input_vec = vec![input; 10];
        let got = dot_product_vec(&input_vec, &elements, num_inputs);
        assert_eq!(got, vec![expected; 10])
    }

    #[test]
    fn test_dot_product_ext() {
        let mut rng = thread_rng();
        let num_inputs = 3;
        // generate the input vectors
        let at = (0..10).map(|_| gen_input(&mut rng)).collect::<Vec<_>>();
        let bt = (0..10).map(|_| gen_input(&mut rng)).collect::<Vec<_>>();
        let ct = (0..10).map(|_| gen_input(&mut rng)).collect::<Vec<_>>();
        // generate the coeffs vectors
        let beta_coeffs_g1: Vec<G1Affine> = random_point_vec(6, &mut rng);
        let alpha_coeffs_g1: Vec<G1Affine> = random_point_vec(6, &mut rng);
        let coeffs_g1: Vec<G1Affine> = random_point_vec(6, &mut rng);

        let got = dot_product_ext::<Bls12_377>(
            (&at, &beta_coeffs_g1),
            (&bt, &alpha_coeffs_g1),
            (&ct, &coeffs_g1),
            num_inputs,
        );

        // it should be the sum of the dot products
        let mut expected = Vec::new();
        for i in 0..at.len() {
            let scalar_at = at[i].iter().map(|e| e.0).collect::<Vec<_>>();
            let scalar_bt = bt[i].iter().map(|e| e.0).collect::<Vec<_>>();
            let scalar_ct = ct[i].iter().map(|e| e.0).collect::<Vec<_>>();
            expected.push(
                get_expected(&beta_coeffs_g1, &scalar_at)
                    + get_expected(&alpha_coeffs_g1, &scalar_bt)
                    + get_expected(&coeffs_g1, &scalar_ct),
            );
        }
        assert_eq!(got, expected);
    }
}
