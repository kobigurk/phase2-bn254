use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use std::{
    fs::File,
    io::{self, BufReader, Read, Write},
    sync::Arc,
};

use bellman_ce::{
    groth16::{Parameters, VerifyingKey},
    pairing::{
        bn256::{Bn256, Fr, G1Affine, G1Uncompressed, G2Affine, G2Uncompressed, G1, G2},
        ff::{Field, PrimeField},
        CurveAffine, CurveProjective, EncodedPoint, Wnaf,
    },
    worker::Worker,
    Circuit, ConstraintSystem, Index, SynthesisError, Variable,
};

use rand::{Rand, Rng};

use super::hash_writer::*;
use super::keypair::*;
use super::keypair_assembly::*;
use super::utils::*;

/// MPC parameters are just like bellman `Parameters` except, when serialized,
/// they contain a transcript of contributions at the end, which can be verified.
#[derive(Clone)]
pub struct MPCParameters {
    params: Parameters<Bn256>,
    cs_hash: [u8; 64],
    contributions: Vec<PublicKey>,
}

impl PartialEq for MPCParameters {
    fn eq(&self, other: &MPCParameters) -> bool {
        self.params == other.params
            && &self.cs_hash[..] == &other.cs_hash[..]
            && self.contributions == other.contributions
    }
}

impl MPCParameters {
    /// Create new Groth16 parameters (compatible with bellman) for a
    /// given circuit. The resulting parameters are unsafe to use
    /// until there are contributions (see `contribute()`).
    pub fn new<C>(
        circuit: C,
        should_filter_points_at_infinity: bool,
    ) -> Result<MPCParameters, SynthesisError>
    where
        C: Circuit<Bn256>,
    {
        let mut assembly = KeypairAssembly {
            num_inputs: 0,
            num_aux: 0,
            num_constraints: 0,
            at_inputs: vec![],
            bt_inputs: vec![],
            ct_inputs: vec![],
            at_aux: vec![],
            bt_aux: vec![],
            ct_aux: vec![],
        };

        // Allocate the "one" input variable
        assembly.alloc_input(|| "", || Ok(Fr::one()))?;

        // Synthesize the circuit.
        circuit.synthesize(&mut assembly)?;

        // Input constraints to ensure full density of IC query
        // x * 0 = 0
        for i in 0..assembly.num_inputs {
            assembly.enforce(
                || "",
                |lc| lc + Variable::new_unchecked(Index::Input(i)),
                |lc| lc,
                |lc| lc,
            );
        }

        // Compute the size of our evaluation domain
        let mut m = 1;
        let mut exp = 0;
        while m < assembly.num_constraints {
            m *= 2;
            exp += 1;

            // Powers of Tau ceremony can't support more than 2^28
            if exp > 28 {
                return Err(SynthesisError::PolynomialDegreeTooLarge);
            }
        }

        // Try to load "phase1radix2m{}"
        let f = match File::open(format!("phase1radix2m{}", exp)) {
            Ok(f) => f,
            Err(e) => {
                panic!("Couldn't load phase1radix2m{}: {:?}", exp, e);
            }
        };
        let f = &mut BufReader::with_capacity(1024 * 1024, f);

        let read_g1 = |reader: &mut BufReader<File>| -> io::Result<G1Affine> {
            let mut repr = G1Uncompressed::empty();
            reader.read_exact(repr.as_mut())?;

            repr.into_affine_unchecked()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
                .and_then(|e| {
                    if e.is_zero() {
                        Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "point at infinity",
                        ))
                    } else {
                        Ok(e)
                    }
                })
        };

        let read_g2 = |reader: &mut BufReader<File>| -> io::Result<G2Affine> {
            let mut repr = G2Uncompressed::empty();
            reader.read_exact(repr.as_mut())?;

            repr.into_affine_unchecked()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
                .and_then(|e| {
                    if e.is_zero() {
                        Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "point at infinity",
                        ))
                    } else {
                        Ok(e)
                    }
                })
        };

        let alpha = read_g1(f)?;
        let beta_g1 = read_g1(f)?;
        let beta_g2 = read_g2(f)?;

        let mut coeffs_g1 = Vec::with_capacity(m);
        for _ in 0..m {
            coeffs_g1.push(read_g1(f)?);
        }

        let mut coeffs_g2 = Vec::with_capacity(m);
        for _ in 0..m {
            coeffs_g2.push(read_g2(f)?);
        }

        let mut alpha_coeffs_g1 = Vec::with_capacity(m);
        for _ in 0..m {
            alpha_coeffs_g1.push(read_g1(f)?);
        }

        let mut beta_coeffs_g1 = Vec::with_capacity(m);
        for _ in 0..m {
            beta_coeffs_g1.push(read_g1(f)?);
        }

        // These are `Arc` so that later it'll be easier
        // to use multiexp during QAP evaluation (which
        // requires a futures-based API)
        let coeffs_g1 = Arc::new(coeffs_g1);
        let coeffs_g2 = Arc::new(coeffs_g2);
        let alpha_coeffs_g1 = Arc::new(alpha_coeffs_g1);
        let beta_coeffs_g1 = Arc::new(beta_coeffs_g1);

        let mut h = Vec::with_capacity(m - 1);
        for _ in 0..m - 1 {
            h.push(read_g1(f)?);
        }

        let mut ic = vec![G1::zero(); assembly.num_inputs];
        let mut l = vec![G1::zero(); assembly.num_aux];
        let mut a_g1 = vec![G1::zero(); assembly.num_inputs + assembly.num_aux];
        let mut b_g1 = vec![G1::zero(); assembly.num_inputs + assembly.num_aux];
        let mut b_g2 = vec![G2::zero(); assembly.num_inputs + assembly.num_aux];

        fn eval(
            // Lagrange coefficients for tau
            coeffs_g1: Arc<Vec<G1Affine>>,
            coeffs_g2: Arc<Vec<G2Affine>>,
            alpha_coeffs_g1: Arc<Vec<G1Affine>>,
            beta_coeffs_g1: Arc<Vec<G1Affine>>,

            // QAP polynomials
            at: &[Vec<(Fr, usize)>],
            bt: &[Vec<(Fr, usize)>],
            ct: &[Vec<(Fr, usize)>],

            // Resulting evaluated QAP polynomials
            a_g1: &mut [G1],
            b_g1: &mut [G1],
            b_g2: &mut [G2],
            ext: &mut [G1],

            // Worker
            worker: &Worker,
        ) {
            // Sanity check
            assert_eq!(a_g1.len(), at.len());
            assert_eq!(a_g1.len(), bt.len());
            assert_eq!(a_g1.len(), ct.len());
            assert_eq!(a_g1.len(), b_g1.len());
            assert_eq!(a_g1.len(), b_g2.len());
            assert_eq!(a_g1.len(), ext.len());

            // Evaluate polynomials in multiple threads
            worker.scope(a_g1.len(), |scope, chunk| {
                for ((((((a_g1, b_g1), b_g2), ext), at), bt), ct) in a_g1
                    .chunks_mut(chunk)
                    .zip(b_g1.chunks_mut(chunk))
                    .zip(b_g2.chunks_mut(chunk))
                    .zip(ext.chunks_mut(chunk))
                    .zip(at.chunks(chunk))
                    .zip(bt.chunks(chunk))
                    .zip(ct.chunks(chunk))
                {
                    let coeffs_g1 = coeffs_g1.clone();
                    let coeffs_g2 = coeffs_g2.clone();
                    let alpha_coeffs_g1 = alpha_coeffs_g1.clone();
                    let beta_coeffs_g1 = beta_coeffs_g1.clone();

                    scope.spawn(move |_| {
                        for ((((((a_g1, b_g1), b_g2), ext), at), bt), ct) in a_g1
                            .iter_mut()
                            .zip(b_g1.iter_mut())
                            .zip(b_g2.iter_mut())
                            .zip(ext.iter_mut())
                            .zip(at.iter())
                            .zip(bt.iter())
                            .zip(ct.iter())
                        {
                            for &(coeff, lag) in at {
                                a_g1.add_assign(&coeffs_g1[lag].mul(coeff));
                                ext.add_assign(&beta_coeffs_g1[lag].mul(coeff));
                            }

                            for &(coeff, lag) in bt {
                                b_g1.add_assign(&coeffs_g1[lag].mul(coeff));
                                b_g2.add_assign(&coeffs_g2[lag].mul(coeff));
                                ext.add_assign(&alpha_coeffs_g1[lag].mul(coeff));
                            }

                            for &(coeff, lag) in ct {
                                ext.add_assign(&coeffs_g1[lag].mul(coeff));
                            }
                        }

                        // Batch normalize
                        G1::batch_normalization(a_g1);
                        G1::batch_normalization(b_g1);
                        G2::batch_normalization(b_g2);
                        G1::batch_normalization(ext);
                    });
                }
            });
        }

        let worker = Worker::new();

        // Evaluate for inputs.
        eval(
            coeffs_g1.clone(),
            coeffs_g2.clone(),
            alpha_coeffs_g1.clone(),
            beta_coeffs_g1.clone(),
            &assembly.at_inputs,
            &assembly.bt_inputs,
            &assembly.ct_inputs,
            &mut a_g1[0..assembly.num_inputs],
            &mut b_g1[0..assembly.num_inputs],
            &mut b_g2[0..assembly.num_inputs],
            &mut ic,
            &worker,
        );

        // Evaluate for auxillary variables.
        eval(
            coeffs_g1.clone(),
            coeffs_g2.clone(),
            alpha_coeffs_g1.clone(),
            beta_coeffs_g1.clone(),
            &assembly.at_aux,
            &assembly.bt_aux,
            &assembly.ct_aux,
            &mut a_g1[assembly.num_inputs..],
            &mut b_g1[assembly.num_inputs..],
            &mut b_g2[assembly.num_inputs..],
            &mut l,
            &worker,
        );

        // Don't allow any elements be unconstrained, so that
        // the L query is always fully dense.
        for e in l.iter() {
            if e.is_zero() {
                return Err(SynthesisError::UnconstrainedVariable);
            }
        }

        let vk = VerifyingKey {
            alpha_g1: alpha,
            beta_g1: beta_g1,
            beta_g2: beta_g2,
            gamma_g2: G2Affine::one(),
            delta_g1: G1Affine::one(),
            delta_g2: G2Affine::one(),
            ic: ic.into_iter().map(|e| e.into_affine()).collect(),
        };

        let params = if should_filter_points_at_infinity {
            Parameters {
                vk: vk,
                h: Arc::new(h),
                l: Arc::new(l.into_iter().map(|e| e.into_affine()).collect()),

                // Filter points at infinity away from A/B queries
                a: Arc::new(
                    a_g1.into_iter()
                        .filter(|e| !e.is_zero())
                        .map(|e| e.into_affine())
                        .collect(),
                ),
                b_g1: Arc::new(
                    b_g1.into_iter()
                        .filter(|e| !e.is_zero())
                        .map(|e| e.into_affine())
                        .collect(),
                ),
                b_g2: Arc::new(
                    b_g2.into_iter()
                        .filter(|e| !e.is_zero())
                        .map(|e| e.into_affine())
                        .collect(),
                ),
            }
        } else {
            Parameters {
                vk: vk,
                h: Arc::new(h),
                l: Arc::new(l.into_iter().map(|e| e.into_affine()).collect()),
                a: Arc::new(a_g1.into_iter().map(|e| e.into_affine()).collect()),
                b_g1: Arc::new(b_g1.into_iter().map(|e| e.into_affine()).collect()),
                b_g2: Arc::new(b_g2.into_iter().map(|e| e.into_affine()).collect()),
            }
        };

        let h = {
            let sink = io::sink();
            let mut sink = HashWriter::new(sink);

            params.write(&mut sink).unwrap();

            sink.into_hash()
        };

        let mut cs_hash = [0; 64];
        cs_hash.copy_from_slice(h.as_ref());

        Ok(MPCParameters {
            params: params,
            cs_hash: cs_hash,
            contributions: vec![],
        })
    }

    /// Get the underlying Groth16 `Parameters`
    pub fn get_params(&self) -> &Parameters<Bn256> {
        &self.params
    }

    /// Contributes some randomness to the parameters. Only one
    /// contributor needs to be honest for the parameters to be
    /// secure.
    ///
    /// This function returns a "hash" that is bound to the
    /// contribution. Contributors can use this hash to make
    /// sure their contribution is in the final parameters, by
    /// checking to see if it appears in the output of
    /// `MPCParameters::verify`.
    pub fn contribute<R: Rng>(&mut self, rng: &mut R) -> [u8; 64] {
        // Generate a keypair
        let (pubkey, privkey) = keypair(rng, self);

        #[cfg(not(feature = "wasm"))]
        fn batch_exp<C: CurveAffine>(bases: &mut [C], coeff: C::Scalar) {
            let coeff = coeff.into_repr();

            let mut projective = vec![C::Projective::zero(); bases.len()];
            let cpus = num_cpus::get();
            let chunk_size = if bases.len() < cpus {
                1
            } else {
                bases.len() / cpus
            };

            // Perform wNAF over multiple cores, placing results into `projective`.
            crossbeam::scope(|scope| {
                for (bases, projective) in bases
                    .chunks_mut(chunk_size)
                    .zip(projective.chunks_mut(chunk_size))
                {
                    scope.spawn(move || {
                        let mut wnaf = Wnaf::new();

                        for (base, projective) in bases.iter_mut().zip(projective.iter_mut()) {
                            *projective = wnaf.base(base.into_projective(), 1).scalar(coeff);
                        }
                    });
                }
            });

            // Perform batch normalization
            crossbeam::scope(|scope| {
                for projective in projective.chunks_mut(chunk_size) {
                    scope.spawn(move || {
                        C::Projective::batch_normalization(projective);
                    });
                }
            });

            // Turn it all back into affine points
            for (projective, affine) in projective.iter().zip(bases.iter_mut()) {
                *affine = projective.into_affine();
            }
        }

        #[cfg(feature = "wasm")]
        fn batch_exp<C: CurveAffine>(bases: &mut [C], coeff: C::Scalar) {
            let coeff = coeff.into_repr();

            let mut projective = vec![C::Projective::zero(); bases.len()];

            // Perform wNAF, placing results into `projective`.
            let mut wnaf = Wnaf::new();
            for (base, projective) in bases.iter_mut().zip(projective.iter_mut()) {
                *projective = wnaf.base(base.into_projective(), 1).scalar(coeff);
            }

            // Perform batch normalization
            C::Projective::batch_normalization(&mut projective);

            // Turn it all back into affine points
            for (projective, affine) in projective.iter().zip(bases.iter_mut()) {
                *affine = projective.into_affine();
            }
        }

        let delta_inv = privkey.delta.inverse().expect("nonzero");
        let mut l = (&self.params.l[..]).to_vec();
        let mut h = (&self.params.h[..]).to_vec();
        batch_exp(&mut l, delta_inv);
        batch_exp(&mut h, delta_inv);
        self.params.l = Arc::new(l);
        self.params.h = Arc::new(h);

        self.params.vk.delta_g1 = self.params.vk.delta_g1.mul(privkey.delta).into_affine();
        self.params.vk.delta_g2 = self.params.vk.delta_g2.mul(privkey.delta).into_affine();

        self.contributions.push(pubkey.clone());

        // Calculate the hash of the public key and return it
        {
            let sink = io::sink();
            let mut sink = HashWriter::new(sink);
            pubkey.write(&mut sink).unwrap();
            let h = sink.into_hash();
            let mut response = [0u8; 64];
            response.copy_from_slice(h.as_ref());
            response
        }
    }

    /// Verify the correctness of the parameters, given a circuit
    /// instance. This will return all of the hashes that
    /// contributors obtained when they ran
    /// `MPCParameters::contribute`, for ensuring that contributions
    /// exist in the final parameters.
    pub fn verify<C: Circuit<Bn256>>(
        &self,
        circuit: C,
        should_filter_points_at_infinity: bool,
    ) -> Result<Vec<[u8; 64]>, ()> {
        let initial_params =
            MPCParameters::new(circuit, should_filter_points_at_infinity).map_err(|_| ())?;

        // H/L will change, but should have same length
        if initial_params.params.h.len() != self.params.h.len() {
            return Err(());
        }
        if initial_params.params.l.len() != self.params.l.len() {
            return Err(());
        }

        // A/B_G1/B_G2 doesn't change at all
        if initial_params.params.a != self.params.a {
            return Err(());
        }
        if initial_params.params.b_g1 != self.params.b_g1 {
            return Err(());
        }
        if initial_params.params.b_g2 != self.params.b_g2 {
            return Err(());
        }

        // alpha/beta/gamma don't change
        if initial_params.params.vk.alpha_g1 != self.params.vk.alpha_g1 {
            return Err(());
        }
        if initial_params.params.vk.beta_g1 != self.params.vk.beta_g1 {
            return Err(());
        }
        if initial_params.params.vk.beta_g2 != self.params.vk.beta_g2 {
            return Err(());
        }
        if initial_params.params.vk.gamma_g2 != self.params.vk.gamma_g2 {
            return Err(());
        }

        // IC shouldn't change, as gamma doesn't change
        if initial_params.params.vk.ic != self.params.vk.ic {
            return Err(());
        }

        // cs_hash should be the same
        if &initial_params.cs_hash[..] != &self.cs_hash[..] {
            return Err(());
        }

        let sink = io::sink();
        let mut sink = HashWriter::new(sink);
        sink.write_all(&initial_params.cs_hash[..]).unwrap();

        let mut current_delta = G1Affine::one();
        let mut result = vec![];

        for pubkey in &self.contributions {
            let mut our_sink = sink.clone();
            our_sink
                .write_all(pubkey.s.into_uncompressed().as_ref())
                .unwrap();
            our_sink
                .write_all(pubkey.s_delta.into_uncompressed().as_ref())
                .unwrap();

            pubkey.write(&mut sink).unwrap();

            let h = our_sink.into_hash();

            // The transcript must be consistent
            if &pubkey.transcript[..] != h.as_ref() {
                return Err(());
            }

            let r = hash_to_g2(h.as_ref()).into_affine();

            // Check the signature of knowledge
            if !same_ratio((r, pubkey.r_delta), (pubkey.s, pubkey.s_delta)) {
                return Err(());
            }

            // Check the change from the old delta is consistent
            if !same_ratio((current_delta, pubkey.delta_after), (r, pubkey.r_delta)) {
                return Err(());
            }

            current_delta = pubkey.delta_after;

            {
                let sink = io::sink();
                let mut sink = HashWriter::new(sink);
                pubkey.write(&mut sink).unwrap();
                let h = sink.into_hash();
                let mut response = [0u8; 64];
                response.copy_from_slice(h.as_ref());
                result.push(response);
            }
        }

        // Current parameters should have consistent delta in G1
        if current_delta != self.params.vk.delta_g1 {
            return Err(());
        }

        // Current parameters should have consistent delta in G2
        if !same_ratio(
            (G1Affine::one(), current_delta),
            (G2Affine::one(), self.params.vk.delta_g2),
        ) {
            return Err(());
        }

        // H and L queries should be updated with delta^-1
        if !same_ratio(
            merge_pairs(&initial_params.params.h, &self.params.h),
            (self.params.vk.delta_g2, G2Affine::one()), // reversed for inverse
        ) {
            return Err(());
        }

        if !same_ratio(
            merge_pairs(&initial_params.params.l, &self.params.l),
            (self.params.vk.delta_g2, G2Affine::one()), // reversed for inverse
        ) {
            return Err(());
        }

        Ok(result)
    }

    /// Serialize these parameters. The serialized parameters
    /// can be read by bellman as Groth16 `Parameters`.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.params.write(&mut writer)?;
        writer.write_all(&self.cs_hash)?;

        writer.write_u32::<BigEndian>(self.contributions.len() as u32)?;
        for pubkey in &self.contributions {
            pubkey.write(&mut writer)?;
        }

        Ok(())
    }

    /// Deserialize these parameters. If `checked` is false,
    /// we won't perform curve validity and group order
    /// checks.
    pub fn read<R: Read>(mut reader: R, checked: bool) -> io::Result<MPCParameters> {
        let params = Parameters::read(&mut reader, checked)?;

        let mut cs_hash = [0u8; 64];
        reader.read_exact(&mut cs_hash)?;

        let contributions_len = reader.read_u32::<BigEndian>()? as usize;

        let mut contributions = vec![];
        for _ in 0..contributions_len {
            contributions.push(PublicKey::read(&mut reader)?);
        }

        Ok(MPCParameters {
            params,
            cs_hash,
            contributions,
        })
    }
}

/// This is a cheap helper utility that exists purely
/// because Rust still doesn't have type-level integers
/// and so doesn't implement `PartialEq` for `[T; 64]`
pub fn contains_contribution(contributions: &[[u8; 64]], my_contribution: &[u8; 64]) -> bool {
    for contrib in contributions {
        if &contrib[..] == &my_contribution[..] {
            return true;
        }
    }

    return false;
}

/// Verify a contribution, given the old parameters and
/// the new parameters. Returns the hash of the contribution.
pub fn verify_contribution(before: &MPCParameters, after: &MPCParameters) -> Result<[u8; 64], ()> {
    // Transformation involves a single new object
    if after.contributions.len() != (before.contributions.len() + 1) {
        return Err(());
    }

    // None of the previous transformations should change
    if &before.contributions[..] != &after.contributions[0..before.contributions.len()] {
        return Err(());
    }

    // H/L will change, but should have same length
    if before.params.h.len() != after.params.h.len() {
        return Err(());
    }
    if before.params.l.len() != after.params.l.len() {
        return Err(());
    }

    // A/B_G1/B_G2 doesn't change at all
    if before.params.a != after.params.a {
        return Err(());
    }
    if before.params.b_g1 != after.params.b_g1 {
        return Err(());
    }
    if before.params.b_g2 != after.params.b_g2 {
        return Err(());
    }

    // alpha/beta/gamma don't change
    if before.params.vk.alpha_g1 != after.params.vk.alpha_g1 {
        return Err(());
    }
    if before.params.vk.beta_g1 != after.params.vk.beta_g1 {
        return Err(());
    }
    if before.params.vk.beta_g2 != after.params.vk.beta_g2 {
        return Err(());
    }
    if before.params.vk.gamma_g2 != after.params.vk.gamma_g2 {
        return Err(());
    }

    // IC shouldn't change, as gamma doesn't change
    if before.params.vk.ic != after.params.vk.ic {
        return Err(());
    }

    // cs_hash should be the same
    if &before.cs_hash[..] != &after.cs_hash[..] {
        return Err(());
    }

    let sink = io::sink();
    let mut sink = HashWriter::new(sink);
    sink.write_all(&before.cs_hash[..]).unwrap();

    for pubkey in &before.contributions {
        pubkey.write(&mut sink).unwrap();
    }

    let pubkey = after.contributions.last().unwrap();
    sink.write_all(pubkey.s.into_uncompressed().as_ref())
        .unwrap();
    sink.write_all(pubkey.s_delta.into_uncompressed().as_ref())
        .unwrap();

    let h = sink.into_hash();

    // The transcript must be consistent
    if &pubkey.transcript[..] != h.as_ref() {
        return Err(());
    }

    let r = hash_to_g2(h.as_ref()).into_affine();

    // Check the signature of knowledge
    if !same_ratio((r, pubkey.r_delta), (pubkey.s, pubkey.s_delta)) {
        return Err(());
    }

    // Check the change from the old delta is consistent
    if !same_ratio(
        (before.params.vk.delta_g1, pubkey.delta_after),
        (r, pubkey.r_delta),
    ) {
        return Err(());
    }

    // Current parameters should have consistent delta in G1
    if pubkey.delta_after != after.params.vk.delta_g1 {
        return Err(());
    }

    // Current parameters should have consistent delta in G2
    if !same_ratio(
        (G1Affine::one(), pubkey.delta_after),
        (G2Affine::one(), after.params.vk.delta_g2),
    ) {
        return Err(());
    }

    // H and L queries should be updated with delta^-1
    if !same_ratio(
        merge_pairs(&before.params.h, &after.params.h),
        (after.params.vk.delta_g2, before.params.vk.delta_g2), // reversed for inverse
    ) {
        return Err(());
    }

    if !same_ratio(
        merge_pairs(&before.params.l, &after.params.l),
        (after.params.vk.delta_g2, before.params.vk.delta_g2), // reversed for inverse
    ) {
        return Err(());
    }

    let sink = io::sink();
    let mut sink = HashWriter::new(sink);
    pubkey.write(&mut sink).unwrap();
    let h = sink.into_hash();
    let mut response = [0u8; 64];
    response.copy_from_slice(h.as_ref());

    Ok(response)
}

/// Compute a keypair, given the current parameters. Keypairs
/// cannot be reused for multiple contributions or contributions
/// in different parameters.
pub fn keypair<R: Rng>(rng: &mut R, current: &MPCParameters) -> (PublicKey, PrivateKey) {
    // Sample random delta
    let delta: Fr = rng.gen();

    // Compute delta s-pair in G1
    let s = G1::rand(rng).into_affine();
    let s_delta = s.mul(delta).into_affine();

    // H(cs_hash | <previous pubkeys> | s | s_delta)
    let h = {
        let sink = io::sink();
        let mut sink = HashWriter::new(sink);

        sink.write_all(&current.cs_hash[..]).unwrap();
        for pubkey in &current.contributions {
            pubkey.write(&mut sink).unwrap();
        }
        sink.write_all(s.into_uncompressed().as_ref()).unwrap();
        sink.write_all(s_delta.into_uncompressed().as_ref())
            .unwrap();

        sink.into_hash()
    };

    // This avoids making a weird assumption about the hash into the
    // group.
    let mut transcript = [0; 64];
    transcript.copy_from_slice(h.as_ref());

    // Compute delta s-pair in G2
    let r = hash_to_g2(h.as_ref()).into_affine();
    let r_delta = r.mul(delta).into_affine();

    (
        PublicKey {
            delta_after: current.params.vk.delta_g1.mul(delta).into_affine(),
            s: s,
            s_delta: s_delta,
            r_delta: r_delta,
            transcript: transcript,
        },
        PrivateKey { delta: delta },
    )
}
