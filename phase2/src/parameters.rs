use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(not(feature = "wasm"))] {
        use super::polynomial::eval;
        use algebra::{ Zero };
        use groth16::{Parameters, VerifyingKey};
        use r1cs_core::SynthesisError;
    }
}

use super::keypair::{hash_cs_pubkeys, Keypair, PublicKey};

use setup_utils::*;

use algebra::{
    AffineCurve, CanonicalDeserialize, CanonicalSerialize, Field, PairingEngine, ProjectiveCurve, SerializationError,
};
use r1cs_core::{lc, ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisMode, Variable};

use rand::Rng;
use std::{
    fmt,
    io::{self, Read, Write},
};

#[derive(Clone, PartialEq, Eq, Debug, Copy)]
pub enum Phase2ContributionMode {
    Full,
    Chunked,
}

/// MPC parameters are just like Zexe's `Parameters` except, when serialized,
/// they contain a transcript of contributions at the end, which can be verified.
#[derive(Clone)]
pub struct MPCParameters<E: PairingEngine> {
    pub params: Parameters<E>,
    pub cs_hash: [u8; 64],
    pub contributions: Vec<PublicKey<E>>,
}

impl<E: PairingEngine> fmt::Debug for MPCParameters<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "MPCParameters {{ params: {:?}, cs_hash: {:?}, contributions: {:?}}}",
            self.params,
            &self.cs_hash[..],
            self.contributions
        )
    }
}

impl<E: PairingEngine + PartialEq> PartialEq for MPCParameters<E> {
    fn eq(&self, other: &MPCParameters<E>) -> bool {
        self.params == other.params
            && &self.cs_hash[..] == other.cs_hash.as_ref()
            && self.contributions == other.contributions
    }
}

impl<E: PairingEngine> MPCParameters<E> {
    #[cfg(not(feature = "wasm"))]
    pub fn new_from_buffer<C>(
        circuit: C,
        transcript: &mut [u8],
        compressed: UseCompression,
        check_input_for_correctness: CheckForCorrectness,
        phase1_size: usize,
        phase2_size: usize,
    ) -> Result<MPCParameters<E>>
    where
        C: ConstraintSynthesizer<E::Fr>,
    {
        let assembly = circuit_to_qap::<E, _>(circuit)?;
        let params = Groth16Params::<E>::read(
            transcript,
            compressed,
            check_input_for_correctness,
            phase1_size,
            phase2_size,
        )?;
        Self::new(assembly, params)
    }

    #[cfg(not(feature = "wasm"))]
    pub fn new_from_buffer_chunked<C>(
        circuit: C,
        transcript: &mut [u8],
        compressed: UseCompression,
        check_input_for_correctness: CheckForCorrectness,
        phase1_size: usize,
        phase2_size: usize,
        chunk_size: usize,
    ) -> Result<(MPCParameters<E>, Parameters<E>, Vec<MPCParameters<E>>)>
    where
        C: ConstraintSynthesizer<E::Fr>,
    {
        let assembly = circuit_to_qap::<E, _>(circuit)?;
        let params = Groth16Params::<E>::read(
            transcript,
            compressed,
            check_input_for_correctness,
            phase1_size,
            phase2_size,
        )?;
        Self::new_chunked(assembly, params, chunk_size)
    }

    #[cfg(not(feature = "wasm"))]
    fn process_matrix(xt: &[Vec<(E::Fr, usize)>], cs: ConstraintSystemRef<E::Fr>) -> Vec<Vec<(E::Fr, usize)>> {
        let mut xt_processed = vec![vec![]; cs.num_instance_variables() + cs.num_witness_variables()];
        for (constraint_num, vars) in xt.iter().enumerate() {
            for (coeff, var_index) in vars {
                xt_processed[*var_index].push((*coeff, constraint_num));
            }
        }
        xt_processed
    }

    /// Create new Groth16 parameters (compatible with Zexe) for a
    /// given QAP which has been produced from a circuit. The resulting parameters
    /// are unsafe to use until there are contributions (see `contribute()`).
    #[cfg(not(feature = "wasm"))]
    pub fn new(cs: ConstraintSystemRef<E::Fr>, params: Groth16Params<E>) -> Result<MPCParameters<E>> {
        // Evaluate the QAP against the coefficients created from phase 1
        let (at, bt, ct) = {
            let matrices = cs.to_matrices().unwrap();
            (matrices.a, matrices.b, matrices.c)
        };

        let at = Self::process_matrix(&at, cs.clone());
        let bt = Self::process_matrix(&bt, cs.clone());
        let ct = Self::process_matrix(&ct, cs.clone());

        let (a_g1, b_g1, b_g2, gamma_abc_g1, l) = eval::<E>(
            // Lagrange coeffs for Tau, read in from Phase 1
            &params.coeffs_g1,
            &params.coeffs_g2,
            &params.alpha_coeffs_g1,
            &params.beta_coeffs_g1,
            // QAP polynomials of the circuit
            &at,
            &bt,
            &ct,
            // Helper
            cs.num_instance_variables(),
        );

        // Reject unconstrained elements, so that
        // the L query is always fully dense.
        for e in l.iter() {
            if e.is_zero() {
                return Err(SynthesisError::UnconstrainedVariable.into());
            }
        }

        let vk = VerifyingKey {
            alpha_g1: params.alpha_g1,
            beta_g2: params.beta_g2,
            // Gamma_g2 is always 1, since we're implementing
            // BGM17, pg14 https://eprint.iacr.org/2017/1050.pdf
            gamma_g2: E::G2Affine::prime_subgroup_generator(),
            delta_g2: E::G2Affine::prime_subgroup_generator(),
            gamma_abc_g1,
        };
        let params = Parameters {
            vk,
            beta_g1: params.beta_g1,
            delta_g1: E::G1Affine::prime_subgroup_generator(),
            a_query: a_g1,
            b_g1_query: b_g1,
            b_g2_query: b_g2,
            h_query: params.h_g1,
            l_query: l,
        };

        let cs_hash = hash_params(&params)?;
        Ok(MPCParameters {
            params,
            cs_hash,
            contributions: vec![],
        })
    }

    #[cfg(not(feature = "wasm"))]
    pub fn new_chunked(
        cs: ConstraintSystemRef<E::Fr>,
        params: Groth16Params<E>,
        chunk_size: usize,
    ) -> Result<(MPCParameters<E>, Parameters<E>, Vec<MPCParameters<E>>)> {
        // Evaluate the QAP against the coefficients created from phase 1
        let (at, bt, ct) = {
            let matrices = cs.to_matrices().unwrap();
            (matrices.a, matrices.b, matrices.c)
        };

        let at = Self::process_matrix(&at, cs.clone());
        let bt = Self::process_matrix(&bt, cs.clone());
        let ct = Self::process_matrix(&ct, cs.clone());

        let (a_g1, b_g1, b_g2, gamma_abc_g1, l) = eval::<E>(
            // Lagrange coeffs for Tau, read in from Phase 1
            &params.coeffs_g1,
            &params.coeffs_g2,
            &params.alpha_coeffs_g1,
            &params.beta_coeffs_g1,
            // QAP polynomials of the circuit
            &at,
            &bt,
            &ct,
            // Helper
            cs.num_instance_variables(),
        );

        // Reject unconstrained elements, so that
        // the L query is always fully dense.
        for e in l.iter() {
            if e.is_zero() {
                return Err(SynthesisError::UnconstrainedVariable.into());
            }
        }

        let vk = VerifyingKey {
            alpha_g1: params.alpha_g1,
            beta_g2: params.beta_g2,
            // Gamma_g2 is always 1, since we're implementing
            // BGM17, pg14 https://eprint.iacr.org/2017/1050.pdf
            gamma_g2: E::G2Affine::prime_subgroup_generator(),
            delta_g2: E::G2Affine::prime_subgroup_generator(),
            gamma_abc_g1,
        };
        let params = Parameters {
            vk,
            beta_g1: params.beta_g1,
            delta_g1: E::G1Affine::prime_subgroup_generator(),
            a_query: a_g1,
            b_g1_query: b_g1,
            b_g2_query: b_g2,
            h_query: params.h_g1,
            l_query: l,
        };

        let query_parameters = Parameters::<E> {
            vk: params.vk.clone(),
            beta_g1: params.beta_g1.clone(),
            delta_g1: params.delta_g1.clone(),
            a_query: params.a_query.clone(),
            b_g1_query: params.b_g1_query.clone(),
            b_g2_query: params.b_g2_query.clone(),
            h_query: vec![],
            l_query: vec![],
        };
        let cs_hash = hash_params(&params)?;
        let full_mpc = MPCParameters {
            params: params.clone(),
            cs_hash,
            contributions: vec![],
        };

        let mut chunks = vec![];
        let max_query = std::cmp::max(params.h_query.len(), params.l_query.len());
        let num_chunks = (max_query + chunk_size - 1) / chunk_size;
        for i in 0..num_chunks {
            let chunk_start = i * chunk_size;
            let chunk_end = (i + 1) * chunk_size;
            let h_query_for_chunk = if chunk_start < params.h_query.len() {
                params.h_query[chunk_start..std::cmp::min(chunk_end, params.h_query.len())].to_vec()
            } else {
                vec![]
            };
            let l_query_for_chunk = if chunk_start < params.l_query.len() {
                params.l_query[chunk_start..std::cmp::min(chunk_end, params.l_query.len())].to_vec()
            } else {
                vec![]
            };
            let chunk_params = MPCParameters {
                params: Parameters::<E> {
                    vk: params.vk.clone(),
                    beta_g1: params.beta_g1.clone(),
                    delta_g1: params.delta_g1.clone(),
                    a_query: vec![],
                    b_g1_query: vec![],
                    b_g2_query: vec![],
                    h_query: h_query_for_chunk,
                    l_query: l_query_for_chunk,
                },
                cs_hash,
                contributions: vec![],
            };
            chunks.push(chunk_params);
        }
        Ok((full_mpc, query_parameters, chunks))
    }

    /// Get the underlying Groth16 `Parameters`
    pub fn get_params(&self) -> &Parameters<E> {
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
    pub fn contribute<R: Rng>(&mut self, batch_exp_mode: BatchExpMode, rng: &mut R) -> Result<[u8; 64]> {
        // Generate a keypair
        let Keypair {
            public_key,
            private_key,
        } = Keypair::new(self.params.delta_g1, self.cs_hash, &self.contributions, rng);

        // Invert delta and multiply the query's `l` and `h` by it
        let delta_inv = private_key.delta.inverse().expect("nonzero");
        batch_mul(&mut self.params.l_query, &delta_inv, batch_exp_mode)?;
        batch_mul(&mut self.params.h_query, &delta_inv, batch_exp_mode)?;

        // Multiply the `delta_g1` and `delta_g2` elements by the private key's delta
        self.params.vk.delta_g2 = self.params.vk.delta_g2.mul(private_key.delta).into_affine();
        self.params.delta_g1 = self.params.delta_g1.mul(private_key.delta).into_affine();
        // Ensure the private key is no longer used
        drop(private_key);
        self.contributions.push(public_key.clone());

        // Return the pubkey's hash
        Ok(public_key.hash())
    }

    /// Verify the correctness of the parameters, given a circuit
    /// instance. This will return all of the hashes that
    /// contributors obtained when they ran
    /// `MPCParameters::contribute`, for ensuring that contributions
    /// exist in the final parameters.
    pub fn verify(&self, after: &Self) -> Result<Vec<[u8; 64]>> {
        let before = self;

        let pubkey = if let Some(pubkey) = after.contributions.last() {
            pubkey
        } else {
            // if there were no contributions then we should error
            return Err(Phase2Error::NoContributions.into());
        };
        // Current parameters should have consistent delta in G1
        ensure_unchanged(pubkey.delta_after, after.params.delta_g1, InvariantKind::DeltaG1)?;
        // Current parameters should have consistent delta in G2
        check_same_ratio::<E>(
            &(E::G1Affine::prime_subgroup_generator(), pubkey.delta_after),
            &(E::G2Affine::prime_subgroup_generator(), after.params.vk.delta_g2),
            "Inconsistent G2 Delta",
        )?;

        // None of the previous transformations should change
        ensure_unchanged(
            &before.contributions[..],
            &after.contributions[0..before.contributions.len()],
            InvariantKind::Contributions,
        )?;

        // cs_hash should be the same
        ensure_unchanged(&before.cs_hash[..], &after.cs_hash[..], InvariantKind::CsHash)?;

        // H/L will change, but should have same length
        ensure_same_length(&before.params.h_query, &after.params.h_query)?;
        ensure_same_length(&before.params.l_query, &after.params.l_query)?;

        // A/B_G1/B_G2/Gamma G1/G2 doesn't change at all
        ensure_unchanged(
            before.params.vk.alpha_g1,
            after.params.vk.alpha_g1,
            InvariantKind::AlphaG1,
        )?;
        ensure_unchanged(before.params.beta_g1, after.params.beta_g1, InvariantKind::BetaG1)?;
        ensure_unchanged(before.params.vk.beta_g2, after.params.vk.beta_g2, InvariantKind::BetaG2)?;
        ensure_unchanged(
            before.params.vk.gamma_g2,
            after.params.vk.gamma_g2,
            InvariantKind::GammaG2,
        )?;
        ensure_unchanged_vec(
            &before.params.vk.gamma_abc_g1,
            &after.params.vk.gamma_abc_g1,
            &InvariantKind::GammaAbcG1,
        )?;

        // === Query related consistency checks ===

        // First 3 queries must be left untouched
        // TODO: Is it absolutely necessary to pass these potentially
        // large vectors around? They're deterministically generated by
        // the circuit being used and the Lagrange coefficients after processing
        // the Powers of Tau from Phase 1, so we could defer construction of the
        // full parameters to the coordinator after all contributions have been
        // collected.
        ensure_unchanged_vec(
            &before.params.a_query,
            &after.params.a_query,
            &InvariantKind::AlphaG1Query,
        )?;

        ensure_unchanged_vec(
            &before.params.b_g1_query,
            &after.params.b_g1_query,
            &InvariantKind::BetaG1Query,
        )?;

        ensure_unchanged_vec(
            &before.params.b_g2_query,
            &after.params.b_g2_query,
            &InvariantKind::BetaG2Query,
        )?;

        // H and L queries should be updated with delta^-1
        if before.params.h_query.len() > 0 {
            check_same_ratio::<E>(
                &merge_pairs(&before.params.h_query, &after.params.h_query),
                &(after.params.vk.delta_g2, before.params.vk.delta_g2), // reversed for inverse
                "H_query ratio check failed",
            )?;
        }

        if before.params.l_query.len() > 0 {
            check_same_ratio::<E>(
                &merge_pairs(&before.params.l_query, &after.params.l_query),
                &(after.params.vk.delta_g2, before.params.vk.delta_g2), // reversed for inverse
                "L_query ratio check failed",
            )?;
        }

        // generate the transcript from the current contributions and the previous cs_hash
        verify_transcript(before.cs_hash, &after.contributions)
    }

    pub fn combine(queries: &Parameters<E>, mpcs: &[MPCParameters<E>]) -> Result<MPCParameters<E>> {
        let mut combined_mpc = MPCParameters::<E> {
            params: Parameters::<E> {
                vk: mpcs[0].params.vk.clone(),
                beta_g1: mpcs[0].params.beta_g1.clone(),
                delta_g1: mpcs[0].params.delta_g1.clone(),
                a_query: queries.a_query.clone(),
                b_g1_query: queries.b_g1_query.clone(),
                b_g2_query: queries.b_g2_query.clone(),
                h_query: vec![],
                l_query: vec![],
            },
            cs_hash: mpcs[0].cs_hash,
            contributions: mpcs[0].contributions.clone(),
        };
        for mpc in mpcs {
            combined_mpc.params.h_query.extend_from_slice(&mpc.params.h_query);
            combined_mpc.params.l_query.extend_from_slice(&mpc.params.l_query);
        }

        Ok(combined_mpc)
    }

    /// Serialize these parameters. The serialized parameters
    /// can be read by Zexe's Groth16 `Parameters`.
    pub fn write<W: Write>(&self, mut writer: W, compressed: UseCompression) -> Result<()> {
        match compressed {
            UseCompression::No => self.params.serialize_uncompressed(&mut writer),
            UseCompression::Yes => self.params.serialize(&mut writer),
        }?;
        writer.write_all(&self.cs_hash)?;
        PublicKey::write_batch(&mut writer, &self.contributions)?;

        Ok(())
    }

    /// Deserialize these parameters.
    pub fn read<R: Read>(
        mut reader: R,
        compressed: UseCompression,
        check_correctness: CheckForCorrectness,
        check_subgroup_membership: bool,
        subgroup_check_mode: SubgroupCheckMode,
    ) -> Result<MPCParameters<E>> {
        let params = match (compressed, check_correctness) {
            (UseCompression::No, CheckForCorrectness::Full) => Parameters::deserialize_uncompressed(&mut reader),
            (UseCompression::Yes, CheckForCorrectness::Full) => Parameters::deserialize(&mut reader),
            (UseCompression::No, CheckForCorrectness::No) | (UseCompression::No, CheckForCorrectness::OnlyNonZero) => {
                Parameters::deserialize_uncompressed_unchecked(&mut reader)
            }
            (UseCompression::Yes, CheckForCorrectness::No)
            | (UseCompression::Yes, CheckForCorrectness::OnlyNonZero) => Parameters::deserialize_unchecked(&mut reader),
            (..) => Err(SerializationError::InvalidData),
        }?;

        // In the Full mode, this is already checked
        if check_subgroup_membership && check_correctness != CheckForCorrectness::Full {
            check_subgroup(&params.a_query, subgroup_check_mode)?;
            check_subgroup(&params.b_g1_query, subgroup_check_mode)?;
            check_subgroup(&params.b_g2_query, subgroup_check_mode)?;
            check_subgroup(&params.h_query, subgroup_check_mode)?;
            check_subgroup(&params.l_query, subgroup_check_mode)?;
            check_subgroup(&params.vk.gamma_abc_g1, subgroup_check_mode)?;
            check_subgroup(
                &vec![params.beta_g1, params.delta_g1, params.vk.alpha_g1],
                subgroup_check_mode,
            )?;
            check_subgroup(
                &vec![params.vk.beta_g2, params.vk.delta_g2, params.vk.gamma_g2],
                subgroup_check_mode,
            )?;
        }

        let mut cs_hash = [0u8; 64];
        reader.read_exact(&mut cs_hash)?;

        let contributions = PublicKey::read_batch(&mut reader)?;

        Ok(MPCParameters {
            params,
            cs_hash,
            contributions,
        })
    }

    pub fn read_fast<R: Read>(
        mut reader: R,
        compressed: UseCompression,
        check_correctness: CheckForCorrectness,
        check_subgroup_membership: bool,
        subgroup_check_mode: SubgroupCheckMode,
    ) -> Result<MPCParameters<E>> {
        let params = Self::read_groth16_fast(
            &mut reader,
            compressed,
            check_correctness,
            check_subgroup_membership,
            subgroup_check_mode,
        )?;

        let mut cs_hash = [0u8; 64];
        reader.read_exact(&mut cs_hash)?;

        let contributions = PublicKey::read_batch(&mut reader)?;

        let mpc_params = MPCParameters::<E> {
            params,
            cs_hash,
            contributions,
        };

        Ok(mpc_params)
    }

    pub fn read_groth16_fast<R: Read>(
        mut reader: R,
        compressed: UseCompression,
        check_correctness: CheckForCorrectness,
        check_subgroup_membership: bool,
        subgroup_check_mode: SubgroupCheckMode,
    ) -> Result<Parameters<E>> {
        // vk
        let alpha_g1: E::G1Affine = reader.read_element(compressed, check_correctness)?;
        let beta_g2: E::G2Affine = reader.read_element(compressed, check_correctness)?;
        let gamma_g2: E::G2Affine = reader.read_element(compressed, check_correctness)?;
        let delta_g2: E::G2Affine = reader.read_element(compressed, check_correctness)?;
        let gamma_abc_g1: Vec<E::G1Affine> = read_vec(&mut reader, compressed, check_correctness)?;

        // rest of the parameters
        let beta_g1: E::G1Affine = reader.read_element(compressed, check_correctness)?;
        let delta_g1: E::G1Affine = reader.read_element(compressed, check_correctness)?;

        // a,b queries guaranteed to have infinity points for variables unused in left,right r1cs
        // inputs respectively
        let ab_query_correctness = match check_correctness {
            CheckForCorrectness::Full => CheckForCorrectness::OnlyInGroup,
            _ => check_correctness,
        };
        let a_query: Vec<E::G1Affine> = read_vec(&mut reader, compressed, ab_query_correctness)?;
        let b_g1_query: Vec<E::G1Affine> = read_vec(&mut reader, compressed, ab_query_correctness)?;
        let b_g2_query: Vec<E::G2Affine> = read_vec(&mut reader, compressed, ab_query_correctness)?;
        let h_query: Vec<E::G1Affine> = read_vec(&mut reader, compressed, check_correctness)?;
        let l_query: Vec<E::G1Affine> = read_vec(&mut reader, compressed, check_correctness)?;

        let params = Parameters::<E> {
            vk: VerifyingKey::<E> {
                alpha_g1,
                beta_g2,
                gamma_g2,
                delta_g2,
                gamma_abc_g1,
            },
            beta_g1,
            delta_g1,
            a_query,
            b_g1_query,
            b_g2_query,
            h_query,
            l_query,
        };

        // In the Full mode, this is already checked
        if check_subgroup_membership && check_correctness != CheckForCorrectness::Full {
            check_subgroup(&params.a_query, subgroup_check_mode)?;
            check_subgroup(&params.b_g1_query, subgroup_check_mode)?;
            check_subgroup(&params.b_g2_query, subgroup_check_mode)?;
            check_subgroup(&params.h_query, subgroup_check_mode)?;
            check_subgroup(&params.l_query, subgroup_check_mode)?;
            check_subgroup(&params.vk.gamma_abc_g1, subgroup_check_mode)?;
            check_subgroup(
                &vec![params.beta_g1, params.delta_g1, params.vk.alpha_g1],
                subgroup_check_mode,
            )?;
            check_subgroup(
                &vec![params.vk.beta_g2, params.vk.delta_g2, params.vk.gamma_g2],
                subgroup_check_mode,
            )?;
        }

        Ok(params)
    }
}

/// This is a cheap helper utility that exists purely
/// because Rust still doesn't have type-level integers
/// and so doesn't implement `PartialEq` for `[T; 64]`
pub fn contains_contribution(contributions: &[[u8; 64]], my_contribution: &[u8; 64]) -> bool {
    for contrib in contributions {
        if &contrib[..] == my_contribution.as_ref() {
            return true;
        }
    }

    false
}

// Helpers for invariant checking
pub fn ensure_same_length<T, U>(a: &[T], b: &[U]) -> Result<()> {
    if a.len() != b.len() {
        return Err(Phase2Error::InvalidLength.into());
    }
    Ok(())
}

pub fn ensure_unchanged_vec<T: PartialEq>(before: &[T], after: &[T], kind: &InvariantKind) -> Result<()> {
    if before.len() != after.len() {
        return Err(Phase2Error::InvalidLength.into());
    }
    for (before, after) in before.iter().zip(after) {
        // TODO: Make the error take a reference
        ensure_unchanged(before, after, kind.clone())?
    }
    Ok(())
}

pub fn ensure_unchanged<T: PartialEq>(before: T, after: T, kind: InvariantKind) -> Result<()> {
    if before != after {
        return Err(Phase2Error::BrokenInvariant(kind).into());
    }
    Ok(())
}

pub fn verify_transcript<E: PairingEngine>(cs_hash: [u8; 64], contributions: &[PublicKey<E>]) -> Result<Vec<[u8; 64]>> {
    let mut result = vec![];
    let mut old_delta = E::G1Affine::prime_subgroup_generator();
    for (i, pubkey) in contributions.iter().enumerate() {
        let hash = hash_cs_pubkeys(cs_hash, &contributions[0..i], pubkey.s, pubkey.s_delta);
        ensure_unchanged(&pubkey.transcript[..], &hash.as_ref()[..], InvariantKind::Transcript)?;

        // generate the G2 point from the hash
        let r = hash_to_g2::<E>(hash.as_ref()).into_affine();

        // Check the signature of knowledge
        check_same_ratio::<E>(
            &(pubkey.s, pubkey.s_delta),
            &(r, pubkey.r_delta),
            "Incorrect signature of knowledge",
        )?;

        // Check the change with the previous G1 Delta is consistent
        check_same_ratio::<E>(
            &(old_delta, pubkey.delta_after),
            &(r, pubkey.r_delta),
            "Inconsistent G1 Delta",
        )?;
        old_delta = pubkey.delta_after;

        result.push(pubkey.hash());
    }

    Ok(result)
}

#[allow(unused)]
fn hash_params<E: PairingEngine>(params: &Parameters<E>) -> Result<[u8; 64]> {
    let sink = io::sink();
    let mut sink = HashWriter::new(sink);
    params.serialize(&mut sink)?;
    let h = sink.into_hash();
    let mut cs_hash = [0; 64];
    cs_hash.copy_from_slice(h.as_ref());
    Ok(cs_hash)
}

/// Converts an R1CS circuit to QAP form
pub fn circuit_to_qap<Zexe: PairingEngine, C: ConstraintSynthesizer<Zexe::Fr>>(
    circuit: C,
) -> Result<ConstraintSystemRef<Zexe::Fr>> {
    // This is a Groth16 keypair assembly
    let cs = ConstraintSystem::new_ref();
    cs.set_mode(SynthesisMode::Setup);

    // Synthesize the circuit.
    circuit
        .generate_constraints(cs.clone())
        .expect("constraint generation should not fail");
    // Input constraints to ensure full density of IC query
    // x * 0 = 0
    for i in 0..cs.num_instance_variables() {
        cs.enforce_constraint(lc!() + Variable::Instance(i), lc!(), lc!())?;
    }
    cs.inline_all_lcs();

    Ok(cs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chunked_groth16::{contribute, verify},
        helpers::testing::TestCircuit,
    };
    use phase1::{helpers::testing::setup_verify, Phase1, Phase1Parameters, ProvingSystem};
    use setup_utils::{Groth16Params, UseCompression};

    use algebra::Bls12_377;

    use rand::thread_rng;
    use tracing_subscriber::{filter::EnvFilter, fmt::Subscriber};

    #[test]
    fn serialize_ceremony() {
        serialize_ceremony_curve::<Bls12_377>()
    }

    fn serialize_ceremony_curve<E: PairingEngine + PartialEq>() {
        let mpc = generate_ceremony::<E>();

        let mut writer = vec![];
        mpc.write(&mut writer, UseCompression::Yes).unwrap();
        let mut reader = vec![0; writer.len()];
        reader.copy_from_slice(&writer);
        let deserialized = MPCParameters::<E>::read(
            &reader[..],
            UseCompression::Yes,
            CheckForCorrectness::Full,
            false,
            SubgroupCheckMode::Auto,
        )
        .unwrap();
        assert_eq!(deserialized, mpc)
    }

    #[test]
    fn verify_with_self_fails() {
        verify_with_self_fails_curve::<Bls12_377>()
    }

    // if there has been no contribution
    // then checking with itself should fail
    fn verify_with_self_fails_curve<E: PairingEngine>() {
        let mpc = generate_ceremony::<E>();
        let err = mpc.verify(&mpc);
        // we handle the error like this because [u8; 64] does not implement
        // debug, meaning we cannot call `assert` on it
        if let Err(e) = err {
            assert_eq!(e.to_string(), "Phase 2 Error: There were no contributions found");
        } else {
            panic!("Verifying with self must fail")
        }
    }
    #[test]
    fn verify_contribution() {
        verify_curve::<Bls12_377>()
    }

    // contributing once and comparing with the previous step passes
    fn verify_curve<E: PairingEngine>() {
        Subscriber::builder()
            .with_target(false)
            .with_env_filter(EnvFilter::from_default_env())
            .init();

        let rng = &mut thread_rng();
        // original
        let mpc = generate_ceremony::<E>();
        let mut mpc_serialized = vec![];
        mpc.write(&mut mpc_serialized, UseCompression::Yes).unwrap();
        let mut mpc_cursor = std::io::Cursor::new(mpc_serialized.clone());

        // first contribution
        let mut contribution1 = mpc.clone();
        contribution1.contribute(BatchExpMode::Auto, rng).unwrap();
        let mut c1_serialized = vec![];
        contribution1.write(&mut c1_serialized, UseCompression::Yes).unwrap();
        let mut c1_cursor = std::io::Cursor::new(c1_serialized.clone());

        // verify it against the previous step
        mpc.verify(&contribution1).unwrap();
        verify::<E>(
            &mut mpc_serialized.as_mut(),
            &mut c1_serialized.as_mut(),
            4,
            UseCompression::Yes,
            CheckForCorrectness::Full,
        )
        .unwrap();
        // after each call on the cursors the cursor's position is at the end,
        // so we have to reset it for further testing!
        mpc_cursor.set_position(0);
        c1_cursor.set_position(0);

        // second contribution via batched method
        let mut c2_buf = c1_serialized.clone();
        c2_buf.resize(c2_buf.len() + PublicKey::<E>::size(), 0); // make the buffer larger by 1 contribution
        contribute::<E, _>(
            &mut c2_buf,
            rng,
            4,
            UseCompression::Yes,
            CheckForCorrectness::Full,
            BatchExpMode::Auto,
        )
        .unwrap();
        let mut c2_cursor = std::io::Cursor::new(c2_buf.clone());
        c2_cursor.set_position(0);

        // verify it against the previous step
        verify::<E>(
            &mut c1_serialized.as_mut(),
            &mut c2_buf.as_mut(),
            4,
            UseCompression::Yes,
            CheckForCorrectness::Full,
        )
        .unwrap();
        c1_cursor.set_position(0);
        c2_cursor.set_position(0);

        // verify it against the original mpc
        verify::<E>(
            &mut mpc_serialized.as_mut(),
            &mut c2_buf.as_mut(),
            4,
            UseCompression::Yes,
            CheckForCorrectness::Full,
        )
        .unwrap();
        mpc_cursor.set_position(0);
        c2_cursor.set_position(0);

        // the de-serialized versions are also compatible
        let contribution2 = MPCParameters::<E>::read(
            &mut c2_cursor,
            UseCompression::Yes,
            CheckForCorrectness::Full,
            false,
            SubgroupCheckMode::Auto,
        )
        .unwrap();
        c2_cursor.set_position(0);
        mpc.verify(&contribution2).unwrap();
        contribution1.verify(&contribution2).unwrap();

        // third contribution
        let mut contribution3 = contribution2.clone();
        contribution3.contribute(BatchExpMode::Auto, rng).unwrap();

        // it's a valid contribution against all previous steps
        mpc.verify(&contribution3).unwrap();
        contribution1.verify(&contribution3).unwrap();
        contribution2.verify(&contribution3).unwrap();
    }

    // helper which generates the initial phase 2 params
    // for the TestCircuit
    fn generate_ceremony<E: PairingEngine>() -> MPCParameters<E> {
        // the phase2 params are generated correctly,
        // even though the powers of tau are >> the circuit size
        let powers = 5;
        let batch = 16;
        let phase2_size = 7;
        let params = Phase1Parameters::<E>::new_full(ProvingSystem::Groth16, powers, batch);
        let accumulator = {
            let compressed = UseCompression::No;
            let (_, output, _, _) = setup_verify(
                compressed,
                CheckForCorrectness::Full,
                compressed,
                BatchExpMode::Auto,
                &params,
            );
            Phase1::deserialize(&output, compressed, CheckForCorrectness::Full, &params).unwrap()
        };

        let groth_params = Groth16Params::<E>::new(
            phase2_size,
            accumulator.tau_powers_g1,
            accumulator.tau_powers_g2,
            accumulator.alpha_tau_powers_g1,
            accumulator.beta_tau_powers_g1,
            accumulator.beta_g2,
        )
        .unwrap();

        // this circuit requires 7 constraints, so a ceremony with size 8 is sufficient
        let c = TestCircuit::<E>(None);
        let assembly = circuit_to_qap::<E, _>(c).unwrap();

        MPCParameters::new(assembly, groth_params).unwrap()
    }
}
