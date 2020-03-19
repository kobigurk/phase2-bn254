/// Utilities to read/write and convert the Powers of Tau from Phase 1
/// to Phase 2-compatible Lagrange Coefficients.
use crate::{buffer_size, write_element, write_elements, Deserializer, Result, UseCompression};
use std::fmt::Debug;
use std::io::Write;
use zexe_algebra::{AffineCurve, PairingEngine, PrimeField, ProjectiveCurve};
use zexe_fft::EvaluationDomain;

#[cfg(feature = "parallel")]
use rayon::prelude::*;
use zexe_fft::{cfg_into_iter, cfg_iter};

#[derive(Debug)]
pub struct Groth16Params<E: PairingEngine> {
    pub alpha_g1: E::G1Affine,
    pub beta_g1: E::G1Affine,
    pub beta_g2: E::G2Affine,
    pub coeffs_g1: Vec<E::G1Affine>,
    pub coeffs_g2: Vec<E::G2Affine>,
    pub alpha_coeffs_g1: Vec<E::G1Affine>,
    pub beta_coeffs_g1: Vec<E::G1Affine>,
    pub h_g1: Vec<E::G1Affine>,
}

impl<E: PairingEngine> PartialEq for Groth16Params<E> {
    fn eq(&self, other: &Self) -> bool {
        self.alpha_g1 == other.alpha_g1
            && self.beta_g1 == other.beta_g1
            && self.beta_g2 == other.beta_g2
            && self.coeffs_g1 == other.coeffs_g1
            && self.coeffs_g2 == other.coeffs_g2
            && self.alpha_coeffs_g1 == other.alpha_coeffs_g1
            && self.beta_coeffs_g1 == other.beta_coeffs_g1
            && self.h_g1 == other.h_g1
    }
}

/// Performs an IFFT over the provided evaluation domain to the provided
/// vector of affine points. It then normalizes and returns them back into
/// affine form
fn to_coeffs<F, C>(domain: &EvaluationDomain<F>, coeffs: &[C]) -> Vec<C>
where
    F: PrimeField,
    C: AffineCurve,
    C::Projective: std::ops::MulAssign<F>,
{
    let mut coeffs = domain.ifft(
        &coeffs
            .iter()
            .map(|e| e.into_projective())
            .collect::<Vec<_>>(),
    );
    C::Projective::batch_normalization(&mut coeffs);
    cfg_iter!(coeffs).map(|p| p.into_affine()).collect()
}

/// H query used in Groth16
/// x^i * (x^m - 1) for i in 0..=(m-2) a.k.a.
/// x^(i + m) - x^i for i in 0..=(m-2)
/// for radix2 evaluation domains
fn h_query_groth16<C: AffineCurve>(powers: Vec<C>, degree: usize) -> Vec<C> {
    cfg_into_iter!(0..degree - 1)
        .map(|i| powers[i + degree] + powers[i].neg())
        .collect()
}

impl<E: PairingEngine> Groth16Params<E> {
    /// Loads the Powers of Tau and transforms them to coefficient form
    /// in preparation of Phase 2
    ///
    /// # Panics
    ///
    /// If `phase2_size` > length of any of the provided vectors
    pub fn new(
        phase2_size: usize,
        tau_powers_g1: Vec<E::G1Affine>,
        tau_powers_g2: Vec<E::G2Affine>,
        alpha_tau_powers_g1: Vec<E::G1Affine>,
        beta_tau_powers_g1: Vec<E::G1Affine>,
        beta_g2: E::G2Affine,
    ) -> Self {
        // Create the evaluation domain
        let domain = EvaluationDomain::<E::Fr>::new(phase2_size).expect("could not create domain");

        // Convert the accumulated powers to Lagrange coefficients
        let coeffs_g1 = to_coeffs(&domain, &tau_powers_g1[0..phase2_size]);
        let coeffs_g2 = to_coeffs(&domain, &tau_powers_g2[0..phase2_size]);
        let alpha_coeffs_g1 = to_coeffs(&domain, &alpha_tau_powers_g1[0..phase2_size]);
        let beta_coeffs_g1 = to_coeffs(&domain, &beta_tau_powers_g1[0..phase2_size]);

        // Calculate the query for the Groth16 proving system
        // todo: we might want to abstract this so that it works generically
        // over various proving systems in the future
        let h_g1 = h_query_groth16(tau_powers_g1, phase2_size);

        Groth16Params {
            alpha_g1: alpha_tau_powers_g1[0],
            beta_g1: beta_tau_powers_g1[0],
            beta_g2,
            coeffs_g1,
            coeffs_g2,
            alpha_coeffs_g1,
            beta_coeffs_g1,
            h_g1,
        }
    }

    /// Writes the data structure to the provided writer, in compressed or uncompressed form.
    pub fn write<W: Write>(&self, writer: &mut W, compression: UseCompression) -> Result<()> {
        // Write alpha (in g1)
        // Needed by verifier for e(alpha, beta)
        // Needed by prover for A and C elements of proof
        write_element(writer, &self.alpha_g1, compression)?;

        // Write beta (in g1)
        // Needed by prover for C element of proof
        write_element(writer, &self.beta_g1, compression)?;

        // Write beta (in g2)
        // Needed by verifier for e(alpha, beta)
        // Needed by prover for B element of proof
        write_element(writer, &self.beta_g2, compression)?;

        // Lagrange coefficients in G1 (for constructing
        // LC/IC queries and precomputing polynomials for A)
        write_elements(writer, &self.coeffs_g1, compression)?;

        // Lagrange coefficients in G2 (for precomputing
        // polynomials for B)
        write_elements(writer, &self.coeffs_g2, compression)?;

        // Lagrange coefficients in G1 with alpha (for
        // LC/IC queries)
        write_elements(writer, &self.alpha_coeffs_g1, compression)?;

        // Lagrange coefficients in G1 with beta (for
        // LC/IC queries)
        write_elements(writer, &self.beta_coeffs_g1, compression)?;

        // Bases for H polynomial computation
        write_elements(writer, &self.h_g1, compression)?;

        Ok(())
    }

    pub fn read(
        (transcript, compressed): (&[u8], UseCompression),
        num_constraints: usize,
    ) -> Result<Groth16Params<E>> {
        // Split the transcript in the appropriate sections
        let (
            in_alpha_g1,
            in_beta_g1,
            in_beta_g2,
            in_coeffs_g1,
            in_coeffs_g2,
            in_alpha_coeffs_g1,
            in_beta_coeffs_g1,
            in_h_g1,
        ) = split_transcript::<E>(transcript, num_constraints, compressed);

        // Read all the necessary elements (this will load A LOT data to your memory for larger ceremonies)
        let alpha_g1 = in_alpha_g1.read_element::<E::G1Affine>(compressed)?;
        let beta_g1 = in_beta_g1.read_element::<E::G1Affine>(compressed)?;
        let beta_g2 = in_beta_g2.read_element::<E::G2Affine>(compressed)?;
        let coeffs_g1 = in_coeffs_g1.read_batch::<E::G1Affine>(compressed)?;
        let coeffs_g2 = in_coeffs_g2.read_batch::<E::G2Affine>(compressed)?;
        let alpha_coeffs_g1 = in_alpha_coeffs_g1.read_batch::<E::G1Affine>(compressed)?;
        let beta_coeffs_g1 = in_beta_coeffs_g1.read_batch::<E::G1Affine>(compressed)?;
        // H query points for Groth 16 should be already processed
        let h_g1 = in_h_g1.read_batch::<E::G1Affine>(compressed)?;

        Ok(Groth16Params {
            alpha_g1,
            beta_g1,
            beta_g2,
            coeffs_g1,
            coeffs_g2,
            alpha_coeffs_g1,
            beta_coeffs_g1,
            h_g1,
        })
    }
}

/// Immutable slices with format [AlphaG1, BetaG1, BetaG2, CoeffsG1, CoeffsG2, AlphaCoeffsG1, BetaCoeffsG1, H_G1]
type SplitBuf<'a> = (
    &'a [u8],
    &'a [u8],
    &'a [u8],
    &'a [u8],
    &'a [u8],
    &'a [u8],
    &'a [u8],
    &'a [u8],
);

/// splits the transcript from phase 1 after it's been prepared and converted to coefficient form
fn split_transcript<E: PairingEngine>(
    input: &[u8],
    size: usize,
    compressed: UseCompression,
) -> SplitBuf {
    let g1_size = buffer_size::<E::G1Affine>(compressed);
    let g2_size = buffer_size::<E::G2Affine>(compressed);

    // 1 element each
    let (alpha_g1, others) = input.split_at(g1_size);
    let (beta_g1, others) = others.split_at(g1_size);
    let (beta_g2, others) = others.split_at(g2_size);

    // N elements per coefficient
    let (coeffs_g1, others) = others.split_at(g1_size * size);
    let (coeffs_g2, others) = others.split_at(g2_size * size);
    let (alpha_coeffs_g1, others) = others.split_at(g1_size * size);
    let (beta_coeffs_g1, others) = others.split_at(g1_size * size);

    // N-1 for the h coeffs
    let (h_coeffs, _) = others.split_at(g1_size * (size - 1));

    (
        alpha_g1,
        beta_g1,
        beta_g2,
        coeffs_g1,
        coeffs_g2,
        alpha_coeffs_g1,
        beta_coeffs_g1,
        h_coeffs,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UseCompression as UseCompressionV1;
    use powersoftau::{parameters::CeremonyParams, BatchedAccumulator};
    use test_helpers::{setup_verify, UseCompression};
    use zexe_algebra::Bls12_377;

    #[test]
    fn first_half_powers() {
        let power = 3 as usize;
        let phase2_size = 2u32.pow(power as u32) as usize / 2;
        read_write_curve::<Bls12_377>(power, phase2_size, UseCompression::Yes);
        read_write_curve::<Bls12_377>(power, phase2_size, UseCompression::No);
    }

    #[test]
    fn phase2_equal_to_powers() {
        let power = 3 as usize;
        let phase2_size = 2u32.pow(power as u32) as usize;
        read_write_curve::<Bls12_377>(power, phase2_size, UseCompression::Yes);
        read_write_curve::<Bls12_377>(power, phase2_size, UseCompression::No);
    }

    #[test]
    #[should_panic]
    fn large_phase2_fails() {
        read_write_curve::<Bls12_377>(3, 9, UseCompression::Yes);
    }

    #[test]
    #[should_panic]
    fn large_phase2_uncompressed_fails() {
        read_write_curve::<Bls12_377>(3, 9, UseCompression::No);
    }

    fn read_write_curve<E: PairingEngine>(
        powers: usize,
        phase2_size: usize,
        compressed: UseCompression,
    ) {
        let batch = 2;
        let params = CeremonyParams::<E>::new(powers, batch);
        let (_, output, _, _) = setup_verify(compressed, compressed, &params);
        let accumulator = BatchedAccumulator::deserialize(&output, compressed, &params).unwrap();

        let groth_params = Groth16Params::<E>::new(
            phase2_size,
            accumulator.tau_powers_g1,
            accumulator.tau_powers_g2,
            accumulator.alpha_tau_powers_g1,
            accumulator.beta_tau_powers_g1,
            accumulator.beta_g2,
        );

        let mut writer = vec![];
        groth_params.write(&mut writer, compat(compressed)).unwrap();
        let mut reader = vec![0; writer.len()];
        reader.copy_from_slice(&writer);
        let deserialized =
            Groth16Params::<E>::read((&reader, compat(compressed)), phase2_size).unwrap();
        assert_eq!(deserialized, groth_params);
    }

    // helper
    fn compat(compression: UseCompression) -> UseCompressionV1 {
        match compression {
            UseCompression::Yes => UseCompressionV1::Yes,
            UseCompression::No => UseCompressionV1::No,
        }
    }
}
