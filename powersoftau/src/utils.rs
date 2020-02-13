use bellman_ce::pairing::ff::{Field, PrimeField, PrimeFieldRepr};
use bellman_ce::pairing::*;
use blake2::{Blake2b, Digest};
use byteorder::{BigEndian, ReadBytesExt};
use generic_array::GenericArray;
use rand::chacha::ChaChaRng;
use rand::{OsRng, Rand, Rng, SeedableRng};

use std::io::{self, Write};
use std::sync::Arc;
use typenum::consts::U64;

use crypto::digest::Digest as CryptoDigest;
use crypto::sha2::Sha256;

use super::parameters::UseCompression;

pub fn print_hash(hash: &[u8]) {
    for line in hash.chunks(16) {
        print!("\t");
        for section in line.chunks(4) {
            for b in section {
                print!("{:02x}", b);
            }
            print!(" ");
        }
        println!();
    }
}

// Create an RNG based on a mixture of system randomness and user provided randomness
pub fn user_system_randomness() -> Vec<u8> {
    let mut system_rng = OsRng::new().unwrap();
    let mut h = Blake2b::default();

    // Gather 1024 bytes of entropy from the system
    for _ in 0..1024 {
        let r: u8 = system_rng.gen();
        h.input(&[r]);
    }

    // Ask the user to provide some information for additional entropy
    let mut user_input = String::new();
    println!("Type some random text and press [ENTER] to provide additional entropy...");
    std::io::stdin()
        .read_line(&mut user_input)
        .expect("expected to read some random text from the user");

    // Hash it all up to make a seed
    h.input(&user_input.as_bytes());
    let arr: GenericArray<u8, U64> = h.result();
    arr.to_vec()
}

#[allow(clippy::modulo_one)]
pub fn beacon_randomness(mut beacon_hash: [u8; 32]) -> [u8; 32] {
    // Performs 2^n hash iterations over it
    const N: u64 = 10;

    for i in 0..(1u64 << N) {
        // Print 1024 of the interstitial states
        // so that verification can be
        // parallelized

        if i % (1u64 << (N - 10)) == 0 {
            print!("{}: ", i);
            for b in beacon_hash.iter() {
                print!("{:02x}", b);
            }
            println!();
        }

        let mut h = Sha256::new();
        h.input(&beacon_hash);
        h.result(&mut beacon_hash);
    }

    print!("Final result of beacon: ");
    for b in beacon_hash.iter() {
        print!("{:02x}", b);
    }
    println!();

    beacon_hash
}

/// Interpret the first 32 bytes of the digest as 8 32-bit words
pub fn get_rng(mut digest: &[u8]) -> impl Rng {
    let mut seed = [0u32; 8];
    for s in &mut seed {
        *s = digest
            .read_u32::<BigEndian>()
            .expect("digest is large enough for this to work");
    }

    ChaChaRng::from_seed(&seed)
}

pub const fn num_bits<T>() -> usize {
    std::mem::size_of::<T>() * 8
}

pub fn log_2(x: u64) -> u32 {
    assert!(x > 0);
    num_bits::<u64>() as u32 - x.leading_zeros() - 1
}

/// Abstraction over a writer which hashes the data being written.
pub struct HashWriter<W: Write> {
    writer: W,
    hasher: Blake2b,
}

impl<W: Write> HashWriter<W> {
    /// Construct a new `HashWriter` given an existing `writer` by value.
    pub fn new(writer: W) -> Self {
        HashWriter {
            writer,
            hasher: Blake2b::default(),
        }
    }

    /// Destroy this writer and return the hash of what was written.
    pub fn into_hash(self) -> GenericArray<u8, U64> {
        self.hasher.result()
    }
}

impl<W: Write> Write for HashWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let bytes = self.writer.write(buf)?;

        if bytes > 0 {
            self.hasher.input(&buf[0..bytes]);
        }

        Ok(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

/// Calculate the contribution hash from the resulting file. Original powers of tau implementation
/// used a specially formed writer to write to the file and calculate a hash on the fly, but memory-constrained
/// implementation now writes without a particular order, so plain recalculation at the end
/// of the procedure is more efficient
pub fn calculate_hash(input_map: &[u8]) -> GenericArray<u8, U64> {
    let chunk_size = 1 << 30; // read by 1GB from map
    let mut hasher = Blake2b::default();
    for chunk in input_map.chunks(chunk_size) {
        hasher.input(&chunk);
    }
    hasher.result()
}

/// Hashes to G2 using the first 32 bytes of `digest`. Panics if `digest` is less
/// than 32 bytes.
pub fn hash_to_g2<E: Engine>(mut digest: &[u8]) -> E::G2 {
    assert!(digest.len() >= 32);

    let mut seed = Vec::with_capacity(8);

    for _ in 0..8 {
        seed.push(
            digest
                .read_u32::<BigEndian>()
                .expect("assertion above guarantees this to work"),
        );
    }

    ChaChaRng::from_seed(&seed).gen()
}

#[cfg(test)]
mod bn256_tests {
    use super::*;
    use bellman_ce::pairing::bn256::{Bn256, Fr, G1Affine, G2Affine};
    use rand::{thread_rng, Rand};

    #[test]
    fn test_hash_to_g2_bn256() {
        assert!(
            hash_to_g2::<Bn256>(&[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32, 33
            ]) == hash_to_g2::<Bn256>(&[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32, 34
            ])
        );

        assert!(
            hash_to_g2::<Bn256>(&[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32
            ]) != hash_to_g2::<Bn256>(&[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 33
            ])
        );
    }

    #[test]
    fn test_same_ratio_bn256() {
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
}

fn merge_pairs<E: Engine, G: CurveAffine<Engine = E, Scalar = E::Fr>>(
    v1: &[G],
    v2: &[G],
) -> (G, G) {
    use rand::thread_rng;

    assert_eq!(v1.len(), v2.len());
    let rng = &mut thread_rng();

    let randomness: Vec<<G::Scalar as PrimeField>::Repr> = (0..v1.len())
        .map(|_| G::Scalar::rand(rng).into_repr())
        .collect();

    let s = dense_multiexp(&v1, &randomness[..]).into_affine();
    let sx = dense_multiexp(&v2, &randomness[..]).into_affine();

    (s, sx)
}

/// Construct a single pair (s, s^x) for a vector of
/// the form [1, x, x^2, x^3, ...].
pub fn power_pairs<E: Engine, G: CurveAffine<Engine = E, Scalar = E::Fr>>(v: &[G]) -> (G, G) {
    merge_pairs::<E, _>(&v[0..(v.len() - 1)], &v[1..])
}

/// Compute BLAKE2b("")
pub fn blank_hash() -> GenericArray<u8, U64> {
    Blake2b::new().result()
}

pub fn reduced_hash(old_power: u8, new_power: u8) -> GenericArray<u8, U64> {
    let mut hasher = Blake2b::new();
    hasher.input(&[old_power, new_power]);
    hasher.result()
}

/// Checks if pairs have the same ratio.
/// Under the hood uses pairing to check
/// x1/x2 = y1/y2 => x1*y2 = x2*y1
pub fn same_ratio<E: Engine, G1: CurveAffine<Engine = E, Scalar = E::Fr>>(
    g1: (G1, G1),
    g2: (G1::Pair, G1::Pair),
) -> bool {
    g1.0.pairing_with(&g2.1) == g1.1.pairing_with(&g2.0)
}

pub fn write_point<W, G>(writer: &mut W, p: &G, compression: UseCompression) -> io::Result<()>
where
    W: Write,
    G: CurveAffine,
{
    match compression {
        UseCompression::Yes => writer.write_all(p.into_compressed().as_ref()),
        UseCompression::No => writer.write_all(p.into_uncompressed().as_ref()),
    }
}

pub fn compute_g2_s<E: Engine>(
    digest: &[u8],
    g1_s: &E::G1Affine,
    g1_s_x: &E::G1Affine,
    personalization: u8,
) -> E::G2Affine {
    let mut h = Blake2b::default();
    h.input(&[personalization]);
    h.input(digest);
    h.input(g1_s.into_uncompressed().as_ref());
    h.input(g1_s_x.into_uncompressed().as_ref());

    hash_to_g2::<E>(h.result().as_ref()).into_affine()
}

/// Perform multi-exponentiation. The caller is responsible for ensuring that
/// the number of bases is the same as the number of exponents.
#[allow(dead_code)]
pub fn dense_multiexp<G: CurveAffine>(
    bases: &[G],
    exponents: &[<G::Scalar as PrimeField>::Repr],
) -> <G as CurveAffine>::Projective {
    if exponents.len() != bases.len() {
        panic!("invalid length")
    }
    let c = if exponents.len() < 32 {
        3u32
    } else {
        (f64::from(exponents.len() as u32)).ln().ceil() as u32
    };

    dense_multiexp_inner(bases, exponents, 0, c, true)
}

fn dense_multiexp_inner<G: CurveAffine>(
    bases: &[G],
    exponents: &[<G::Scalar as PrimeField>::Repr],
    mut skip: u32,
    c: u32,
    handle_trivial: bool,
) -> <G as CurveAffine>::Projective {
    use std::sync::Mutex;
    // Perform this region of the multiexp. We use a different strategy - go over region in parallel,
    // then over another region, etc. No Arc required
    let chunk = (bases.len() / num_cpus::get()) + 1;
    let this = {
        // let mask = (1u64 << c) - 1u64;
        let this_region = Mutex::new(<G as CurveAffine>::Projective::zero());
        let arc = Arc::new(this_region);
        crossbeam::scope(|scope| {
            for (base, exp) in bases.chunks(chunk).zip(exponents.chunks(chunk)) {
                let this_region_rwlock = arc.clone();
                // let handle =
                scope.spawn(move || {
                    let mut buckets = vec![<G as CurveAffine>::Projective::zero(); (1 << c) - 1];
                    // Accumulate the result
                    let mut acc = G::Projective::zero();
                    let zero = G::Scalar::zero().into_repr();
                    let one = G::Scalar::one().into_repr();

                    for (base, &exp) in base.iter().zip(exp.iter()) {
                        // let index = (exp.as_ref()[0] & mask) as usize;

                        // if index != 0 {
                        //     buckets[index - 1].add_assign_mixed(base);
                        // }

                        // exp.shr(c as u32);

                        if exp != zero {
                            if exp == one {
                                if handle_trivial {
                                    acc.add_assign_mixed(base);
                                }
                            } else {
                                let mut exp = exp;
                                exp.shr(skip);
                                let exp = exp.as_ref()[0] % (1 << c);
                                if exp != 0 {
                                    buckets[(exp - 1) as usize].add_assign_mixed(base);
                                }
                            }
                        }
                    }

                    // buckets are filled with the corresponding accumulated value, now sum
                    let mut running_sum = G::Projective::zero();
                    for exp in buckets.into_iter().rev() {
                        running_sum.add_assign(&exp);
                        acc.add_assign(&running_sum);
                    }

                    let mut guard = this_region_rwlock.lock().expect("poisoned");

                    (*guard).add_assign(&acc);
                });
            }
        });

        let this_region = Arc::try_unwrap(arc).unwrap();

        this_region.into_inner().unwrap()
    };

    skip += c;

    if skip >= <G::Scalar as PrimeField>::NUM_BITS {
        // There isn't another region, and this will be the highest region
        this
    } else {
        // next region is actually higher than this one, so double it enough times
        let mut next_region = dense_multiexp_inner(bases, exponents, skip, c, false);
        for _ in 0..c {
            next_region.double();
        }

        next_region.add_assign(&this);

        next_region
    }
}
