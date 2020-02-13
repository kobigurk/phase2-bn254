use std::io::{self, Read, Write};

use bellman_ce::pairing::{
    bn256::{Fr, G1Affine, G1Uncompressed, G2Affine, G2Uncompressed},
    CurveAffine, EncodedPoint,
};

/// This needs to be destroyed by at least one participant
/// for the final parameters to be secure.
pub struct PrivateKey {
    pub delta: Fr,
}

/// This allows others to verify that you contributed. The hash produced
/// by `MPCParameters::contribute` is just a BLAKE2b hash of this object.
#[derive(Clone)]
pub struct PublicKey {
    /// This is the delta (in G1) after the transformation, kept so that we
    /// can check correctness of the public keys without having the entire
    /// interstitial parameters for each contribution.
    pub delta_after: G1Affine,

    /// Random element chosen by the contributor.
    pub s: G1Affine,

    /// That element, taken to the contributor's secret delta.
    pub s_delta: G1Affine,

    /// r is H(last_pubkey | s | s_delta), r_delta proves knowledge of delta
    pub r_delta: G2Affine,

    /// Hash of the transcript (used for mapping to r)
    pub transcript: [u8; 64],
}

impl PublicKey {
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(self.delta_after.into_uncompressed().as_ref())?;
        writer.write_all(self.s.into_uncompressed().as_ref())?;
        writer.write_all(self.s_delta.into_uncompressed().as_ref())?;
        writer.write_all(self.r_delta.into_uncompressed().as_ref())?;
        writer.write_all(&self.transcript)?;

        Ok(())
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<PublicKey> {
        let mut g1_repr = G1Uncompressed::empty();
        let mut g2_repr = G2Uncompressed::empty();

        reader.read_exact(g1_repr.as_mut())?;
        let delta_after = g1_repr
            .into_affine()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        if delta_after.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "point at infinity",
            ));
        }

        reader.read_exact(g1_repr.as_mut())?;
        let s = g1_repr
            .into_affine()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        if s.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "point at infinity",
            ));
        }

        reader.read_exact(g1_repr.as_mut())?;
        let s_delta = g1_repr
            .into_affine()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        if s_delta.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "point at infinity",
            ));
        }

        reader.read_exact(g2_repr.as_mut())?;
        let r_delta = g2_repr
            .into_affine()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        if r_delta.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "point at infinity",
            ));
        }

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

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        self.delta_after == other.delta_after
            && self.s == other.s
            && self.s_delta == other.s_delta
            && self.r_delta == other.r_delta
            && &self.transcript[..] == &other.transcript[..]
    }
}
