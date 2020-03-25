//! # Keypair
//!
//! A Groth16 keypair. Generate one with the Keypair::new method.
//! Dispose of the private key ASAP once it's been used.
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use rand::Rng;
use snark_utils::{hash_to_g2, Deserializer, HashWriter, Result, Serializer, UseCompression};
use std::fmt;
use std::io::{self, Read, Write};
use zexe_algebra::{AffineCurve, PairingEngine, ProjectiveCurve, UniformRand};

/// This needs to be destroyed by at least one participant
/// for the final parameters to be secure.
pub struct PrivateKey<E: PairingEngine> {
    pub delta: E::Fr,
}

pub const PUBKEY_SIZE: usize = 544; // 96 * 2 + 48 * 2 * 3 + 64, assuming uncompressed elements

/// This allows others to verify that you contributed. The hash produced
/// by `MPCParameters::contribute` is just a BLAKE2b hash of this object.
#[derive(Clone)]
pub struct PublicKey<E: PairingEngine> {
    /// This is the delta (in G1) after the transformation, kept so that we
    /// can check correctness of the public keys without having the entire
    /// interstitial parameters for each contribution.
    pub delta_after: E::G1Affine,

    /// Random element chosen by the contributor.
    pub s: E::G1Affine,

    /// That element, taken to the contributor's secret delta.
    pub s_delta: E::G1Affine,

    /// r is H(last_pubkey | s | s_delta), r_delta proves knowledge of delta
    pub r_delta: E::G2Affine,

    /// Hash of the transcript (used for mapping to r)
    pub transcript: [u8; 64],
}

impl<E: PairingEngine> PublicKey<E> {
    /// Returns the Blake2b hash of the public key
    pub fn hash(&self) -> [u8; 64] {
        let sink = io::sink();
        let mut sink = HashWriter::new(sink);
        self.write(&mut sink).unwrap();
        let h = sink.into_hash();
        let mut response = [0u8; 64];
        response.copy_from_slice(h.as_ref());
        response
    }

    pub fn write_batch<W: Write>(writer: &mut W, pubkeys: &[PublicKey<E>]) -> Result<()> {
        writer.write_u32::<BigEndian>(pubkeys.len() as u32)?;
        for pubkey in pubkeys {
            pubkey.write(writer)?;
        }
        Ok(())
    }

    pub fn read_batch<R: Read>(reader: &mut R) -> Result<Vec<Self>> {
        let mut contributions = vec![];
        let contributions_len = reader.read_u32::<BigEndian>()? as usize;
        for _ in 0..contributions_len {
            contributions.push(PublicKey::read(reader)?);
        }
        Ok(contributions)
    }

    /// Serializes the key's **uncompressed** points to the provided
    /// writer
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_element(&self.delta_after, UseCompression::No)?;
        writer.write_element(&self.s, UseCompression::No)?;
        writer.write_element(&self.s_delta, UseCompression::No)?;
        writer.write_element(&self.r_delta, UseCompression::No)?;
        writer.write_all(&self.transcript)?;
        Ok(())
    }

    /// Reads the key's **uncompressed** points from the provided
    /// reader
    pub fn read<R: Read>(reader: &mut R) -> Result<PublicKey<E>> {
        let delta_after = reader.read_element(UseCompression::No)?;
        let s = reader.read_element(UseCompression::No)?;
        let s_delta = reader.read_element(UseCompression::No)?;
        let r_delta = reader.read_element(UseCompression::No)?;
        let mut transcript = [0u8; 64];
        reader.read_exact(&mut transcript)?;

        Ok(PublicKey {
            delta_after,
            s,
            s_delta,
            r_delta,
            transcript,
        })
    }
}

/// A keypair for Groth16
pub struct Keypair<E: PairingEngine> {
    /// Private key which contains the toxic waste
    pub private_key: PrivateKey<E>,
    pub public_key: PublicKey<E>,
}

impl<E: PairingEngine> Keypair<E> {
    /// Compute a keypair, given the current parameters. Keypairs
    /// cannot be reused for multiple contributions or contributions
    /// in different parameters.
    pub fn new(
        delta_g1: E::G1Affine,
        cs_hash: [u8; 64],
        contributions: &[PublicKey<E>],
        rng: &mut impl Rng,
    ) -> Self {
        // Sample random delta -- THIS MUST BE DESTROYED
        let delta: E::Fr = E::Fr::rand(rng);
        let delta_after = delta_g1.mul(delta).into_affine();

        // Compute delta s-pair in G1
        let s = E::G1Projective::rand(rng).into_affine();
        let s_delta = s.mul(delta).into_affine();

        // Get the transcript
        let transcript = hash_cs_pubkeys(cs_hash, contributions, s, s_delta);
        // Compute delta s-pair in G2 by hashing the transcript and multiplying it by delta
        let r = hash_to_g2::<E>(&transcript[..]).into_affine();
        let r_delta = r.mul(delta).into_affine();

        Self {
            public_key: PublicKey {
                delta_after,
                s,
                s_delta,
                r_delta,
                transcript,
            },
            private_key: PrivateKey { delta },
        }
    }
}

/// Returns the transcript hash so far.
///
/// Internally calculates: `H(cs_hash | <contributions> | s | s_delta)`
pub fn hash_cs_pubkeys<E: PairingEngine>(
    cs_hash: [u8; 64],
    contributions: &[PublicKey<E>],
    s: E::G1Affine,
    s_delta: E::G1Affine,
) -> [u8; 64] {
    let h = {
        let sink = io::sink();
        let mut sink = HashWriter::new(sink);

        sink.write_all(&cs_hash[..]).unwrap();
        for pubkey in contributions {
            pubkey.write(&mut sink).unwrap();
        }
        // Write s and s_delta!
        sink.write_element(&s, UseCompression::Yes).unwrap();
        sink.write_element(&s_delta, UseCompression::Yes).unwrap();
        sink.into_hash()
    };
    // This avoids making a weird assumption about the hash into the
    // group.
    let mut transcript = [0; 64];
    transcript.copy_from_slice(h.as_ref());
    transcript
}

impl<E: PairingEngine> fmt::Debug for PublicKey<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PublicKey {{ delta_after: {}, s: {:?}, s_delta: {:?} r_delta: {:?}, transcript : {:?}}}", self.delta_after, self.s, self.s_delta, self.r_delta, &self.transcript[..])
    }
}

impl<E: PairingEngine> PartialEq for PublicKey<E> {
    fn eq(&self, other: &PublicKey<E>) -> bool {
        self.delta_after == other.delta_after
            && self.s == other.s
            && self.s_delta == other.s_delta
            && self.r_delta == other.r_delta
            && &self.transcript[..] == other.transcript.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use zexe_algebra::Bls12_377;

    #[test]
    fn serialization() {
        serialization_curve::<Bls12_377>()
    }

    fn serialization_curve<E: PairingEngine>() {
        let mut rng = thread_rng();
        let delta_g1 = E::G1Affine::prime_subgroup_generator();

        let keypair = Keypair::<E>::new(delta_g1, [0; 64], &[], &mut rng);
        let pubkey = keypair.public_key;

        let mut writer = vec![];
        pubkey.write(&mut writer).unwrap();

        // 3 * 96 + 1 * 192 + 64
        assert_eq!(writer.len(), 544);

        // try to read from it
        let mut reader = vec![0; writer.len()];
        reader.copy_from_slice(&writer);
        let deserialized = PublicKey::<E>::read(&mut &reader[..]).unwrap();
        assert_eq!(deserialized, pubkey);
    }
}
