use crate::parameters::PowersOfTauParameters;

#[derive(Clone)]
pub struct Bn256CeremonyParameters {}

impl PowersOfTauParameters for Bn256CeremonyParameters {
    #[cfg(not(feature = "smalltest"))]
    const REQUIRED_POWER: usize = 28;

    #[cfg(feature = "smalltest")]
    const REQUIRED_POWER: usize = 10;
    #[cfg(feature = "smalltest")]
    const EMPIRICAL_BATCH_SIZE: usize = 1 << 8;

    // This ceremony is based on the BN256 elliptic curve construction.
    const G1_UNCOMPRESSED_BYTE_SIZE: usize = 64;
    const G2_UNCOMPRESSED_BYTE_SIZE: usize = 128;
    const G1_COMPRESSED_BYTE_SIZE: usize = 32;
    const G2_COMPRESSED_BYTE_SIZE: usize = 64;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accumulator::*;
    use crate::{
        keypair::{keypair, PublicKey},
        parameters::{CheckForCorrectness, UseCompression},
        utils::{power_pairs, same_ratio},
    };
    use bellman_ce::pairing::{
        bn256::{Bn256, Fr, G1Affine, G2Affine},
        ff::Field,
        CurveAffine, CurveProjective,
    };
    use rand::{thread_rng, Rand, Rng};

    #[test]
    fn test_pubkey_serialization() {
        let rng = &mut thread_rng();
        let digest = (0..64).map(|_| rng.gen()).collect::<Vec<_>>();
        let (pk, _) = keypair::<_, Bn256>(rng, &digest);
        let mut v = vec![];
        pk.serialize(&mut v).unwrap();
        assert_eq!(v.len(), Bn256CeremonyParameters::PUBLIC_KEY_SIZE);
        let deserialized = PublicKey::<Bn256>::deserialize(&mut &v[..]).unwrap();
        assert!(pk == deserialized);
    }

    #[test]
    fn test_power_pairs() {
        let rng = &mut thread_rng();

        let mut v = vec![];
        let x = Fr::rand(rng);
        let mut acc = Fr::one();
        for _ in 0..100 {
            v.push(G1Affine::one().mul(acc).into_affine());
            acc.mul_assign(&x);
        }

        let gx = G2Affine::one().mul(x).into_affine();

        assert!(same_ratio(power_pairs(&v), (G2Affine::one(), gx)));

        v[1] = v[1].mul(Fr::rand(rng)).into_affine();

        assert!(!same_ratio(power_pairs(&v), (G2Affine::one(), gx)));
    }

    #[test]
    fn test_same_ratio() {
        let rng = &mut thread_rng();

        let s = Fr::rand(rng);
        let g1 = G1Affine::one();
        let g2 = G2Affine::one();
        let g1_s = g1.mul(s).into_affine();
        let g2_s = g2.mul(s).into_affine();

        assert!(same_ratio((g1, g1_s), (g2, g2_s)));
        assert!(!same_ratio((g1_s, g1), (g2, g2_s)));
    }

    #[test]
    fn test_accumulator_serialization() {
        let rng = &mut thread_rng();
        let mut digest = (0..64).map(|_| rng.gen()).collect::<Vec<_>>();
        let params = Bn256CeremonyParameters {};
        let mut acc = Accumulator::<Bn256, _>::new(params.clone());
        let before = acc.clone();
        let (pk, sk) = keypair::<_, Bn256>(rng, &digest);
        acc.transform(&sk);
        assert!(verify_transform(&before, &acc, &pk, &digest));
        digest[0] = !digest[0];
        assert!(!verify_transform(&before, &acc, &pk, &digest));
        let mut v = Vec::with_capacity(Bn256CeremonyParameters::ACCUMULATOR_BYTE_SIZE - 64);
        acc.serialize(&mut v, UseCompression::No).unwrap();
        assert_eq!(v.len(), Bn256CeremonyParameters::ACCUMULATOR_BYTE_SIZE - 64);
        let deserialized = Accumulator::deserialize(
            &mut &v[..],
            UseCompression::No,
            CheckForCorrectness::No,
            params,
        )
        .unwrap();
        assert!(acc == deserialized);
    }
}
