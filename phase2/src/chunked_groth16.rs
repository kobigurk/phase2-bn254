//! Chunked Phase 2
//!
//! Large MPCs can require >50GB of elements to be loaded in memory. This module provides
//! utilities for operating directly on raw items which implement `Read`, `Write` and `Seek`
//! such that contributing and verifying the MPC can be done in chunks which fit in memory.
use crate::keypair::{Keypair, PublicKey, PUBKEY_SIZE};
use byteorder::{BigEndian, WriteBytesExt};
use rand::Rng;
use snark_utils::{batch_mul, Result};
use std::{
    io::{Read, Seek, SeekFrom, Write},
    ops::Neg,
};
use zexe_algebra::{
    AffineCurve, CanonicalDeserialize, CanonicalSerialize, ConstantSerializedSize, Field,
    PairingEngine, ProjectiveCurve,
};
use zexe_groth16::VerifyingKey;

/// Given a buffer which corresponds to the format of `MPCParameters` (Groth16 Parameters
/// followed by the contributions array and the contributions hash), this will modify the
/// Delta_g1, the VK's Delta_g2 and will update the H and L queries in place while leaving
/// everything else unchanged
pub fn contribute<E: PairingEngine, B: Read + Write + Seek, R: Rng>(
    buffer: &mut B,
    rng: &mut R,
    batch_size: usize,
) -> Result<[u8; 64]> {
    // The VK is small so we read it directly from the start
    let mut vk = VerifyingKey::<E>::deserialize(buffer)?;
    // leave beta_g1 unchanged
    buffer.seek(SeekFrom::Current(E::G1Affine::SERIALIZED_SIZE as i64))?;
    // read delta_g1
    let mut delta_g1 = E::G1Affine::deserialize(buffer)?;

    // Skip the vector elements for now so that we can read the contributions
    skip_vec::<E::G1Affine, _>(buffer)?; // Alpha G1
    skip_vec::<E::G1Affine, _>(buffer)?; // Beta G1
    skip_vec::<E::G2Affine, _>(buffer)?; // Beta G2
    skip_vec::<E::G1Affine, _>(buffer)?; // H
    skip_vec::<E::G1Affine, _>(buffer)?; // L

    // Read the transcript hash and the contributions
    let mut cs_hash = [0u8; 64];
    buffer.read_exact(&mut cs_hash)?;
    let contributions = PublicKey::<E>::read_batch(buffer)?;

    // Create the keypair
    let Keypair {
        public_key,
        private_key,
    } = Keypair::new(delta_g1, cs_hash, &contributions, rng);
    let hash = public_key.hash();
    // THIS MUST BE DESTROYED
    let delta = private_key.delta;
    let delta_inv = private_key.delta.inverse().expect("nonzero");

    // update the values
    delta_g1 = delta_g1.mul(delta).into_affine();
    vk.delta_g2 = vk.delta_g2.mul(delta).into_affine();

    // go back to the start of the buffer to write the updated vk and delta_g1
    buffer.seek(SeekFrom::Start(0))?;
    // write the vk
    vk.serialize(buffer)?;
    // leave beta_g1 unchanged
    buffer.seek(SeekFrom::Current(E::G1Affine::SERIALIZED_SIZE as i64))?;
    // write delta_g1
    delta_g1.serialize(buffer)?;

    skip_vec::<E::G1Affine, _>(buffer)?; // Alpha G1
    skip_vec::<E::G1Affine, _>(buffer)?; // Beta G1
    skip_vec::<E::G2Affine, _>(buffer)?; // Beta G2

    // update the h_query
    chunked_mul_queries::<E::G1Affine, _>(buffer, &delta_inv, batch_size)?;
    // update the l_query
    chunked_mul_queries::<E::G1Affine, _>(buffer, &delta_inv, batch_size)?;

    // leave the cs_hash unchanged (64 bytes size)
    buffer.seek(SeekFrom::Current(64))?;

    // update the pubkeys length
    buffer.write_u32::<BigEndian>((contributions.len() + 1) as u32)?;

    // advance to where the next pubkey would be in the buffer and append it
    buffer.seek(SeekFrom::Current(
        (PUBKEY_SIZE * contributions.len()) as i64,
    ))?;
    public_key.write(buffer)?;

    Ok(hash)
}

/// Skips the vector ahead of the cursor.
fn skip_vec<C: AffineCurve, B: Read + Seek>(buffer: &mut B) -> Result<()> {
    let len = u64::deserialize(buffer)? as usize;
    let skip_len = len * C::SERIALIZED_SIZE;
    buffer.seek(SeekFrom::Current(skip_len as i64))?;
    Ok(())
}

/// Multiplies a vector of affine elements by `element` in `batch_size` batches
/// The first 8 bytes read from the buffer are the vector's length. The result
/// is written back to the buffer in place
fn chunked_mul_queries<C: AffineCurve, B: Read + Write + Seek>(
    buffer: &mut B,
    element: &C::ScalarField,
    batch_size: usize,
) -> Result<()> {
    // read total length
    let query_len = u64::deserialize(buffer)? as usize;

    let iters = query_len / batch_size;
    let leftovers = query_len % batch_size;
    // naive chunking, probably room for parallelization
    for _ in 0..iters {
        mul_query::<C, _>(buffer, element, batch_size)?;
    }
    // in case the batch size did not evenly divide the number of queries
    if leftovers > 0 {
        mul_query::<C, _>(buffer, element, leftovers)?;
    }

    Ok(())
}

/// Deserializes `num_els` elements, multiplies them by `element`
/// and writes them back in place
fn mul_query<C: AffineCurve, B: Read + Write + Seek>(
    buffer: &mut B,
    element: &C::ScalarField,
    num_els: usize,
) -> Result<()> {
    let mut query = (0..num_els)
        .map(|_| C::deserialize(buffer))
        .collect::<std::result::Result<Vec<_>, _>>()?; // why can't we use the aliased error type here?

    batch_mul(&mut query, element)?;

    // seek back to update the elements
    buffer.seek(SeekFrom::Current(
        ((num_els * C::SERIALIZED_SIZE) as i64).neg(),
    ))?;
    query
        .iter()
        .map(|el| el.serialize(buffer))
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(())
}
