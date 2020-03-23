use rand::Rng;
use zexe_algebra::{
    AffineCurve, CanonicalDeserialize, CanonicalSerialize, PairingEngine, ProjectiveCurve,
    SerializationError, UniformRand,
};

use super::parameters::CeremonyParams;
use snark_utils::{compute_g2_s, Error, UseCompression};
use std::io::{Read, Write};

/// Contains terms of the form (s<sub>1</sub>, s<sub>1</sub><sup>x</sup>, H(s<sub>1</sub><sup>x</sup>)<sub>2</sub>, H(s<sub>1</sub><sup>x</sup>)<sub>2</sub><sup>x</sup>)
/// for all x in τ, α and β, and some s chosen randomly by its creator. The function H "hashes into" the group G2. No points in the public key may be the identity.
///
/// The elements in G2 are used to verify transformations of the accumulator. By its nature, the public key proves
/// knowledge of τ, α and β.
///
/// It is necessary to verify `same_ratio`((s<sub>1</sub>, s<sub>1</sub><sup>x</sup>), (H(s<sub>1</sub><sup>x</sup>)<sub>2</sub>, H(s<sub>1</sub><sup>x</sup>)<sub>2</sub><sup>x</sup>)).
#[derive(Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicKey<E: PairingEngine> {
    pub tau_g1: (E::G1Affine, E::G1Affine),
    pub alpha_g1: (E::G1Affine, E::G1Affine),
    pub beta_g1: (E::G1Affine, E::G1Affine),
    pub tau_g2: E::G2Affine,
    pub alpha_g2: E::G2Affine,
    pub beta_g2: E::G2Affine,
}

impl<E: PairingEngine> PartialEq for PublicKey<E> {
    fn eq(&self, other: &PublicKey<E>) -> bool {
        self.tau_g1.0 == other.tau_g1.0
            && self.tau_g1.1 == other.tau_g1.1
            && self.alpha_g1.0 == other.alpha_g1.0
            && self.alpha_g1.1 == other.alpha_g1.1
            && self.beta_g1.0 == other.beta_g1.0
            && self.beta_g1.1 == other.beta_g1.1
            && self.tau_g2 == other.tau_g2
            && self.alpha_g2 == other.alpha_g2
            && self.beta_g2 == other.beta_g2
    }
}

/// Contains the secrets τ, α and β that the participant of the ceremony must destroy.
#[derive(PartialEq, Debug)]
pub struct PrivateKey<E: PairingEngine> {
    pub tau: E::Fr,
    pub alpha: E::Fr,
    pub beta: E::Fr,
}

/// Constructs a keypair given an RNG and a 64-byte transcript `digest`.
pub fn keypair<E: PairingEngine, R: Rng>(
    rng: &mut R,
    digest: &[u8],
) -> Result<(PublicKey<E>, PrivateKey<E>), Error> {
    if digest.len() != 64 {
        return Err(Error::InvalidLength {
            expected: 64,
            got: digest.len(),
        });
    }

    // tau is a contribution to the "powers of tau", in a set of points of the form "tau^i * G"
    let tau = E::Fr::rand(rng);
    // alpha and beta are a set of contributions in a form "alpha * tau^i * G" and that are required
    // for construction of the polynomials
    let alpha = E::Fr::rand(rng);
    let beta = E::Fr::rand(rng);

    let mut op = |x: E::Fr, personalization: u8| -> Result<_, Error> {
        // Sample random g^s
        let g1_s = E::G1Projective::rand(rng).into_affine();
        // Compute g^{s*x}
        let g1_s_x = g1_s.mul(x).into_affine();
        // Hash into G2 as g^{s'}
        let g2_s: E::G2Affine = compute_g2_s::<E>(&digest, &g1_s, &g1_s_x, personalization)?;
        // Compute g^{s'*x}
        let g2_s_x = g2_s.mul(x).into_affine();

        Ok(((g1_s, g1_s_x), g2_s_x))
    };

    // these "public keys" are required for the next participants to check that points are in fact
    // sequential powers
    let pk_tau = op(tau, 0)?;
    let pk_alpha = op(alpha, 1)?;
    let pk_beta = op(beta, 2)?;

    Ok((
        PublicKey {
            tau_g1: pk_tau.0,
            alpha_g1: pk_alpha.0,
            beta_g1: pk_beta.0,
            tau_g2: pk_tau.1,
            alpha_g2: pk_alpha.1,
            beta_g2: pk_beta.1,
        },
        PrivateKey { tau, alpha, beta },
    ))
}

impl<E: PairingEngine> PublicKey<E> {
    /// Writes the key to the memory map (takes into account offsets)
    pub fn write(
        &self,
        output_map: &mut [u8],
        accumulator_was_compressed: UseCompression,
        parameters: &CeremonyParams<E>,
    ) -> Result<(), Error> {
        let position = match accumulator_was_compressed {
            UseCompression::Yes => parameters.contribution_size - parameters.public_key_size,
            UseCompression::No => parameters.accumulator_size,
        };
        // Write the public key after the provided position
        self.serialize(&mut output_map[position..].as_mut())?;

        Ok(())
    }

    /// Deserialize the public key from the memory map (takes into account offsets)
    pub fn read(
        input_map: &[u8],
        accumulator_was_compressed: UseCompression,
        parameters: &CeremonyParams<E>,
    ) -> Result<Self, Error> {
        let position = match accumulator_was_compressed {
            UseCompression::Yes => parameters.contribution_size - parameters.public_key_size,
            UseCompression::No => parameters.accumulator_size,
        };
        // The public key is written after the provided position
        Ok(PublicKey::deserialize(&mut &input_map[position..])?)
    }
}
