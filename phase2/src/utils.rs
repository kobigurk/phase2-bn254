extern crate bellman_ce;
extern crate rand;
extern crate byteorder;

use byteorder::{
    BigEndian,
    ReadBytesExt,
};
use num_bigint::BigUint;
use num_traits::Num;
use std::sync::Arc;
use bellman_ce::pairing::{
    ff::{
        PrimeField,
    },
    CurveAffine,
    CurveProjective,
    Wnaf,
    bn256::{
        G2,
        G1Affine,
        G2Affine,
        Fq12,
    }
};
use rand::{
    Rng,
    Rand,
    ChaChaRng,
    SeedableRng
};


/// Checks if pairs have the same ratio.
pub fn same_ratio<G1: CurveAffine>(
    g1: (G1, G1),
    g2: (G1::Pair, G1::Pair)
) -> bool
{
    if g1.0.is_zero() || g1.1.is_zero() || g2.0.is_zero() || g2.1.is_zero() {
        panic!(format!("none of the inputs should be zero: {}, {}, {}, {}", g1.0, g1.1, g2.0, g2.1));
    }
    g1.0.pairing_with(&g2.1) == g1.1.pairing_with(&g2.0)
}

/// Computes a random linear combination over v1/v2.
///
/// Checking that many pairs of elements are exponentiated by
/// the same `x` can be achieved (with high probability) with
/// the following technique:
///
/// Given v1 = [a, b, c] and v2 = [as, bs, cs], compute
/// (a*r1 + b*r2 + c*r3, (as)*r1 + (bs)*r2 + (cs)*r3) for some
/// random r1, r2, r3. Given (g, g^s)...
///
/// e(g, (as)*r1 + (bs)*r2 + (cs)*r3) = e(g^s, a*r1 + b*r2 + c*r3)
///
/// ... with high probability.
pub fn merge_pairs<G: CurveAffine>(v1: &[G], v2: &[G]) -> (G, G)
{
    use std::sync::Mutex;
    use rand::{thread_rng};

    assert_eq!(v1.len(), v2.len());

    let chunk = (v1.len() / num_cpus::get()) + 1;

    let s = Arc::new(Mutex::new(G::Projective::zero()));
    let sx = Arc::new(Mutex::new(G::Projective::zero()));

    crossbeam::scope(|scope| {
        for (v1, v2) in v1.chunks(chunk).zip(v2.chunks(chunk)) {
            let s = s.clone();
            let sx = sx.clone();

            scope.spawn(move |_| {
                // We do not need to be overly cautious of the RNG
                // used for this check.
                let rng = &mut thread_rng();

                let mut wnaf = Wnaf::new();
                let mut local_s = G::Projective::zero();
                let mut local_sx = G::Projective::zero();

                for (v1, v2) in v1.iter().zip(v2.iter()) {
                    let rho = G::Scalar::rand(rng);
                    let mut wnaf = wnaf.scalar(rho.into_repr());
                    let v1 = wnaf.base(v1.into_projective());
                    let v2 = wnaf.base(v2.into_projective());

                    local_s.add_assign(&v1);
                    local_sx.add_assign(&v2);
                }

                s.lock().unwrap().add_assign(&local_s);
                sx.lock().unwrap().add_assign(&local_sx);
            });
        }
    }).unwrap();

    let s = s.lock().unwrap().into_affine();
    let sx = sx.lock().unwrap().into_affine();

    (s, sx)
}



/// Hashes to G2 using the first 32 bytes of `digest`. Panics if `digest` is less
/// than 32 bytes. The input must be random.
pub fn hash_to_g2(mut digest: &[u8]) -> G2
{
    assert!(digest.len() >= 32);

    let mut seed = Vec::with_capacity(8);

    for _ in 0..8 {
        seed.push(digest.read_u32::<BigEndian>().expect("assertion above guarantees this to work"));
    }

    ChaChaRng::from_seed(&seed).gen()
}

pub fn repr_to_big<T: std::fmt::Display>(r: T) -> String {
    BigUint::from_str_radix(&format!("{}", r)[2..], 16).unwrap().to_str_radix(10)
}

pub fn p1_to_vec(p: &G1Affine) -> Vec<String> {
    return vec![
        repr_to_big(p.get_x().into_repr()),
        repr_to_big(p.get_y().into_repr()),
        if p.is_zero() { "0".to_string() } else { "1".to_string() }
    ]
}

pub fn p2_to_vec(p: &G2Affine) -> Vec<Vec<String>> {
    return vec![
        vec![
            repr_to_big(p.get_x().c0.into_repr()),
            repr_to_big(p.get_x().c1.into_repr()),
        ],
        vec![
            repr_to_big(p.get_y().c0.into_repr()),
            repr_to_big(p.get_y().c1.into_repr()),
        ],
        if p.is_zero() {
            vec!["0".to_string(), "0".to_string()]
        } else {
            vec!["1".to_string(), "0".to_string()]
        }
    ]
}

pub fn pairing_to_vec(p: &Fq12) -> Vec<Vec<Vec<String>>> {
    return vec![
        vec![
            vec![
                repr_to_big(p.c0.c0.c0.into_repr()),
                repr_to_big(p.c0.c0.c1.into_repr()),
            ],
            vec![
                repr_to_big(p.c0.c1.c0.into_repr()),
                repr_to_big(p.c0.c1.c1.into_repr()),
            ],
            vec![
                repr_to_big(p.c0.c2.c0.into_repr()),
                repr_to_big(p.c0.c2.c1.into_repr()),
            ]
        ],
        vec![
            vec![
                repr_to_big(p.c1.c0.c0.into_repr()),
                repr_to_big(p.c1.c0.c1.into_repr()),
            ],
            vec![
                repr_to_big(p.c1.c1.c0.into_repr()),
                repr_to_big(p.c1.c1.c1.into_repr()),
            ],
            vec![
                repr_to_big(p.c1.c2.c0.into_repr()),
                repr_to_big(p.c1.c2.c1.into_repr()),
            ]
        ],
    ]
}
