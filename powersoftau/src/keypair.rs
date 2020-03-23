use rand::Rng;
use zexe_algebra::{
    serialize::ConstantSerializedSize, AffineCurve, PairingEngine, ProjectiveCurve, UniformRand,
};

use super::parameters::CeremonyParams;
use snark_utils::{compute_g2_s, write_elements, BatchDeserializer, Error, UseCompression};

/// Contains terms of the form (s<sub>1</sub>, s<sub>1</sub><sup>x</sup>, H(s<sub>1</sub><sup>x</sup>)<sub>2</sub>, H(s<sub>1</sub><sup>x</sup>)<sub>2</sub><sup>x</sup>)
/// for all x in τ, α and β, and some s chosen randomly by its creator. The function H "hashes into" the group G2. No points in the public key may be the identity.
///
/// The elements in G2 are used to verify transformations of the accumulator. By its nature, the public key proves
/// knowledge of τ, α and β.
///
/// It is necessary to verify `same_ratio`((s<sub>1</sub>, s<sub>1</sub><sup>x</sup>), (H(s<sub>1</sub><sup>x</sup>)<sub>2</sub>, H(s<sub>1</sub><sup>x</sup>)<sub>2</sub><sup>x</sup>)).
#[derive(Eq, Debug)]
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
    /// Serialize the public key. Points are always in uncompressed form.
    pub fn serialize(&self, writer: &mut [u8]) -> Result<(), Error> {
        let g1_size = E::G1Affine::UNCOMPRESSED_SIZE;
        let g1_elements = &[
            self.tau_g1.0,
            self.tau_g1.1,
            self.alpha_g1.0,
            self.alpha_g1.1,
            self.beta_g1.0,
            self.beta_g1.1,
        ];
        // Serialize the G1 elements of the key
        write_elements(
            &mut writer[..6 * g1_size].as_mut(),
            g1_elements,
            UseCompression::No,
        )?;

        let g2_elements = &[self.tau_g2, self.alpha_g2, self.beta_g2];
        // Serialize the G2 elements of the key (note that we take the writer after the
        // index of the 6 G1 elements)
        write_elements(
            &mut writer[6 * g1_size..].as_mut(),
            g2_elements,
            UseCompression::No,
        )?;

        Ok(())
    }

    /// Deserialize the public key. Points are always in uncompressed form, and
    /// always checked, since there aren't very many of them. Does not allow an
    /// points at infinity.
    pub fn deserialize(reader: &[u8]) -> Result<PublicKey<E>, Error> {
        let g1_size = E::G1Affine::UNCOMPRESSED_SIZE;
        // Deserialize the first 6 G1 elements
        let g1_els = (&reader[..6 * g1_size]).read_batch(UseCompression::No)?;
        // Deserialize the remaining 3 G2 elements
        let g2_els = (&reader[6 * g1_size..]).read_batch(UseCompression::No)?;

        Ok(PublicKey {
            tau_g1: (g1_els[0], g1_els[1]),
            alpha_g1: (g1_els[2], g1_els[3]),
            beta_g1: (g1_els[4], g1_els[5]),
            tau_g2: g2_els[0],
            alpha_g2: g2_els[1],
            beta_g2: g2_els[2],
        })
    }
}

impl<E: PairingEngine> PublicKey<E> {
    /// This function is intended to write the key to the memory map and calculates
    /// a position for writing into the file itself based on information whether
    /// contribution was output in compressed on uncompressed form
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
        self.serialize(&mut output_map[position..])?;

        Ok(())
    }

    /// Deserialize the public key. Points are always in uncompressed form, and
    /// always checked, since there aren't very many of them. Does not allow any
    /// points at infinity.
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
        PublicKey::deserialize(&input_map[position..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parameters::CurveParams;
    use rand::{thread_rng, Rng};
    use zexe_algebra::{bls12_377::Bls12_377, bls12_381::Bls12_381, sw6::SW6};

    #[test]
    fn test_pubkey_serialization_bls12_381() {
        test_pubkey_serialization_curve::<Bls12_381>();
    }

    #[test]
    fn test_pubkey_serialization_bls12_377() {
        test_pubkey_serialization_curve::<Bls12_377>();
    }

    #[test]
    fn test_pubkey_serialization_sw6() {
        test_pubkey_serialization_curve::<SW6>();
    }

    fn test_pubkey_serialization_curve<E: PairingEngine>() {
        let curve = CurveParams::<E>::new();
        let public_key_size = 6 * curve.g1 + 3 * curve.g2;

        // Generate a random public key
        let rng = &mut thread_rng();
        let digest = (0..64).map(|_| rng.gen()).collect::<Vec<_>>();
        let err = keypair::<E, _>(rng, &[]).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Invalid variable length: expected 64, got 0"
        );
        let (pk, _): (PublicKey<E>, _) = keypair(rng, &digest).unwrap();

        // Serialize it
        let mut v = vec![0; public_key_size];
        pk.serialize(&mut v).unwrap();
        assert_eq!(v.len(), public_key_size);

        // Deserialize it and check that it matches
        let deserialized = PublicKey::<E>::deserialize(&v[..]).unwrap();
        assert!(pk == deserialized);
    }
}
