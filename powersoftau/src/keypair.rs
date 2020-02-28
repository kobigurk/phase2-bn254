use rand::Rng;
use zexe_algebra::{AffineCurve, PairingEngine, ProjectiveCurve, UniformRand};

use super::parameters::CeremonyParams;
use snark_utils::{compute_g2_s, Error, UseCompression};

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
    pub fn serialize(
        &self,
        writer: &mut [u8],
        g1_size: usize,
        g2_size: usize,
    ) -> Result<(), Error> {
        let g1_elements = &[
            self.tau_g1.0,
            self.tau_g1.1,
            self.alpha_g1.0,
            self.alpha_g1.1,
            self.beta_g1.0,
            self.beta_g1.1,
        ];
        // Serialize the G1 elements of the key
        write_elements(writer, g1_elements, g1_size, UseCompression::No)?;

        let g2_elements = &[self.tau_g2, self.alpha_g2, self.beta_g2];
        // Serialize the G2 elements of the key (note that we take the writer after the
        // index of the 6 G1 elements)
        write_elements(
            &mut writer[6 * g1_size..],
            g2_elements,
            g2_size,
            UseCompression::No,
        )?;

        Ok(())
    }

    /// Deserialize the public key. Points are always in uncompressed form, and
    /// always checked, since there aren't very many of them. Does not allow any
    /// points at infinity.
    pub fn deserialize(
        reader: &[u8],
        g1_size: usize,
        g2_size: usize,
    ) -> Result<PublicKey<E>, Error> {
        // Deserialize the first 6 G1 elements
        let g1_els = read_elements::<E::G1Affine>(reader, 6, g1_size, UseCompression::No)?;
        // Deserialize the next 3 G2 elements
        let g2_els =
            read_elements::<E::G2Affine>(&reader[6 * g1_size..], 3, g2_size, UseCompression::No)?;

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
        self.serialize(
            &mut output_map[position..],
            parameters.curve.g1,
            parameters.curve.g2,
        )?;

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
        PublicKey::deserialize(
            &input_map[position..],
            parameters.curve.g1,
            parameters.curve.g2,
        )
    }
}

/// Writes the provided array of elements of `group_size` each to the provided buffer
fn write_elements(
    buffer: &mut [u8],
    elements: &[impl AffineCurve],
    group_size: usize,
    compressed: UseCompression,
) -> Result<(), Error> {
    for (i, element) in elements.iter().enumerate() {
        if compressed == UseCompression::Yes {
            element.serialize(&[], &mut buffer[i * group_size..(i + 1) * group_size])?;
        } else {
            element.serialize_uncompressed(&mut buffer[i * group_size..(i + 1) * group_size])?;
        }
    }

    Ok(())
}

/// Reads `num_elements` of `group_size` each from `buffer`
fn read_elements<G: AffineCurve>(
    buffer: &[u8],
    num_elements: usize,
    group_size: usize,
    compressed: UseCompression,
) -> Result<Vec<G>, Error> {
    let mut ret = Vec::with_capacity(num_elements);
    for i in 0..num_elements {
        let element = if compressed == UseCompression::Yes {
            G::deserialize(
                &buffer[i * group_size..(i + 1) * group_size],
                &mut [false; 0],
            )?
        } else {
            G::deserialize_uncompressed(&buffer[i * group_size..(i + 1) * group_size])?
        };
        ret.push(element);
    }
    Ok(ret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parameters::CurveParams;
    use rand::{thread_rng, Rng};
    use snark_utils::ElementType;
    use test_helpers::random_point_vec;
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
        pk.serialize(&mut v, curve.g1, curve.g2).unwrap();
        assert_eq!(v.len(), public_key_size);

        // Deserialize it and check that it matches
        let deserialized = PublicKey::<E>::deserialize(&v[..], curve.g1, curve.g2).unwrap();
        assert!(pk == deserialized);
    }

    #[test]
    fn test_point_serialization_bls12_381() {
        test_point_serialization_curve::<Bls12_381>();
    }

    #[test]
    fn test_point_serialization_bls12_377() {
        test_point_serialization_curve::<Bls12_377>();
    }

    #[test]
    fn test_point_serialization_sw6() {
        test_point_serialization_curve::<SW6>();
    }

    fn test_point_serialization_curve<E: PairingEngine>() {
        let curve = CurveParams::<E>::new();

        test_point::<E::G1Affine, _>(&curve, ElementType::TauG1, UseCompression::No);
        test_point::<E::G1Affine, _>(&curve, ElementType::TauG1, UseCompression::Yes);
        test_point::<E::G2Affine, _>(&curve, ElementType::TauG2, UseCompression::No);
        test_point::<E::G2Affine, _>(&curve, ElementType::TauG2, UseCompression::Yes);
    }

    fn test_point<G: AffineCurve, E>(
        curve: &CurveParams<E>,
        element_type: ElementType,
        compression: UseCompression,
    ) {
        let rng = &mut thread_rng();
        let num_el = 10;
        let group_size = curve.get_size(element_type, compression);

        // generate a bunch of random elements
        let elements: Vec<G> = random_point_vec(num_el, rng);

        let buffer_len = num_el * group_size;
        let mut buffer = vec![0; buffer_len];

        // write them in the buffer
        write_elements(&mut buffer, &elements, group_size, compression).unwrap();

        // deserialize and check that they match
        let deserialized: Vec<G> = read_elements(&buffer, num_el, group_size, compression).unwrap();
        assert_eq!(deserialized, elements);
    }
}
