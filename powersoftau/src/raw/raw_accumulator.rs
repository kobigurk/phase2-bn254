//! Accumulator which operates on batches of data

use crate::{
    keypair::{PrivateKey, PublicKey},
    parameters::CeremonyParams,
};
use itertools::{Itertools, MinMaxResult};
use snark_utils::*;
use snark_utils::{Deserializer, Serializer};
use zexe_algebra::{AffineCurve, PairingEngine, ProjectiveCurve, Zero};

/// Mutable buffer, compression
type Output<'a> = (&'a mut [u8], UseCompression);
/// Buffer, compression
type Input<'a> = (&'a [u8], UseCompression);

/// Mutable slices with format [TauG1, TauG2, AlphaG1, BetaG1, BetaG2]
type SplitBufMut<'a> = (
    &'a mut [u8],
    &'a mut [u8],
    &'a mut [u8],
    &'a mut [u8],
    &'a mut [u8],
);

/// Immutable slices with format [TauG1, TauG2, AlphaG1, BetaG1, BetaG2]
type SplitBuf<'a> = (&'a [u8], &'a [u8], &'a [u8], &'a [u8], &'a [u8]);

#[allow(type_alias_bounds)]
type AccumulatorElements<E: PairingEngine> = (
    Vec<E::G1Affine>,
    Vec<E::G2Affine>,
    Vec<E::G1Affine>,
    Vec<E::G1Affine>,
    E::G2Affine,
);

#[allow(type_alias_bounds)]
#[allow(unused)]
type AccumulatorElementsRef<'a, E: PairingEngine> = (
    &'a [E::G1Affine],
    &'a [E::G2Affine],
    &'a [E::G1Affine],
    &'a [E::G1Affine],
    &'a E::G2Affine,
);

/// Helper function to iterate over the accumulator in chunks.
/// `action` will perform an action on the chunk
fn iter_chunk(
    parameters: &CeremonyParams<impl PairingEngine>,
    mut action: impl FnMut(usize, usize) -> Result<()>,
) -> Result<()> {
    (0..parameters.powers_g1_length)
        .chunks(parameters.batch_size)
        .into_iter()
        .map(|chunk| {
            let (start, end) = match chunk.minmax() {
                MinMaxResult::MinMax(start, end) => (start, end + 1),
                MinMaxResult::OneElement(start) => (start, start + 1),
                _ => return Err(Error::InvalidChunk),
            };
            action(start, end)
        })
        .collect::<Result<_>>()
}

/// Populates the output buffer with an empty accumulator as dictated by Parameters and compression
pub fn init<'a, E: PairingEngine>(
    output: &'a mut [u8],
    parameters: &'a CeremonyParams<E>,
    compressed: UseCompression,
) {
    let (tau_g1, tau_g2, alpha_g1, beta_g1, beta_g2) = split_mut(output, parameters, compressed);
    let g1_size = buffer_size::<E::G1Affine>(compressed);
    let g2_size = buffer_size::<E::G2Affine>(compressed);
    let g1_one = &E::G1Affine::prime_subgroup_generator();
    let g2_one = &E::G2Affine::prime_subgroup_generator();
    rayon::scope(|s| {
        s.spawn(|_| {
            tau_g1
                .init_element(g1_one, g1_size, compressed)
                .expect("could not initialize TauG1 elements")
        });
        s.spawn(|_| {
            tau_g2
                .init_element(g2_one, g2_size, compressed)
                .expect("could not initialize TauG2 elements")
        });
        s.spawn(|_| {
            alpha_g1
                .init_element(g1_one, g1_size, compressed)
                .expect("could not initialize Alpha G1 elements")
        });
        s.spawn(|_| {
            beta_g1
                .init_element(g1_one, g1_size, compressed)
                .expect("could not initialize Beta G1 elements")
        });
        s.spawn(|_| {
            beta_g2
                .init_element(g2_one, g2_size, compressed)
                .expect("could not initialize the Beta G2 element")
        });
    });
}

/// Given a public key and the accumulator's digest, it hashes each G1 element
/// along with the digest, and then hashes it to G2.
fn compute_g2_s_key<E: PairingEngine>(
    key: &PublicKey<E>,
    digest: &[u8],
) -> Result<[E::G2Affine; 3]> {
    Ok([
        compute_g2_s::<E>(&digest, &key.tau_g1.0, &key.tau_g1.1, 0)?,
        compute_g2_s::<E>(&digest, &key.alpha_g1.0, &key.alpha_g1.1, 1)?,
        compute_g2_s::<E>(&digest, &key.beta_g1.0, &key.beta_g1.1, 2)?,
    ])
}

/// Reads a list of G1 elements from the buffer to the provided `elements` slice
/// and then checks that their powers pairs ratio matches the one from the
/// provided `check` pair
fn check_power_ratios<E: PairingEngine>(
    (buffer, compression): (&[u8], UseCompression),
    (start, end): (usize, usize),
    elements: &mut [E::G1Affine],
    check: &(E::G2Affine, E::G2Affine),
) -> Result<()> {
    let size = buffer_size::<E::G1Affine>(compression);
    buffer[start * size..end * size]
        .par_read_batch_preallocated(&mut elements[0..end - start], compression)?;
    check_same_ratio::<E>(&power_pairs(&elements[..end - start]), check, "Power pairs")?;
    Ok(())
}

/// Reads a list of G2 elements from the buffer to the provided `elements` slice
/// and then checks that their powers pairs ratio matches the one from the
/// provided `check` pair
fn check_power_ratios_g2<E: PairingEngine>(
    (buffer, compression): (&[u8], UseCompression),
    (start, end): (usize, usize),
    elements: &mut [E::G2Affine],
    check: &(E::G1Affine, E::G1Affine),
) -> Result<()> {
    let size = buffer_size::<E::G2Affine>(compression);
    buffer[start * size..end * size]
        .par_read_batch_preallocated(&mut elements[0..end - start], compression)?;
    check_same_ratio::<E>(check, &power_pairs(&elements[..end - start]), "Power pairs")?;
    Ok(())
}

/// Reads a chunk of 2 elements from the buffer
fn read_initial_elements<C: AffineCurve>(buf: &[u8], compressed: UseCompression) -> Result<Vec<C>> {
    let batch = 2;
    let size = buffer_size::<C>(compressed);
    let ret = buf[0..batch * size].par_read_batch(compressed)?;
    if ret.len() != batch {
        return Err(Error::InvalidLength {
            expected: batch,
            got: ret.len(),
        });
    }
    Ok(ret)
}

/// Verifies that the accumulator was transformed correctly
/// given the `PublicKey` and the so-far hash of the accumulator
pub fn verify<E: PairingEngine>(
    (input, compressed_input): (&[u8], UseCompression),
    (output, compressed_output): (&[u8], UseCompression),
    key: &PublicKey<E>,
    digest: &[u8],
    parameters: &CeremonyParams<E>,
) -> Result<()> {
    // Ensure the key ratios are correctly produced
    let [tau_g2_s, alpha_g2_s, beta_g2_s] = compute_g2_s_key(&key, &digest)?;
    // put in tuple form for convenience
    let tau_g2_check = &(tau_g2_s, key.tau_g2);
    let alpha_g2_check = &(alpha_g2_s, key.alpha_g2);
    let beta_g2_check = &(beta_g2_s, key.beta_g2);
    // Check the proofs-of-knowledge for tau/alpha/beta
    let check_ratios = &[
        (key.tau_g1, tau_g2_check, "Tau G1<>G2"),
        (key.alpha_g1, alpha_g2_check, "Alpha G1<>G2"),
        (key.beta_g1, beta_g2_check, "Beta G1<>G2"),
    ];
    for (a, b, err) in check_ratios {
        check_same_ratio::<E>(a, b, err)?;
    }

    // Split the buffers
    // todo: check that in_tau_g2 is actually not required
    let (in_tau_g1, _, in_alpha_g1, in_beta_g1, in_beta_g2) =
        split(input, parameters, compressed_input);
    let (tau_g1, tau_g2, alpha_g1, beta_g1, beta_g2) = split(output, parameters, compressed_output);

    // Ensure that the initial conditions are correctly formed (first 2 elements)
    // We allocate a G1 vector of length 2 and re-use it for our G1 elements.
    // We keep the values of the Tau G1/G2 telements for later use.
    let (g1_check, g2_check) = {
        let mut before_g1 = read_initial_elements::<E::G1Affine>(in_tau_g1, compressed_input)?;
        let mut after_g1 = read_initial_elements::<E::G1Affine>(tau_g1, compressed_output)?;
        if after_g1[0] != E::G1Affine::prime_subgroup_generator() {
            return Err(VerificationError::InvalidGenerator(ElementType::TauG1).into());
        }
        let after_g2 = read_initial_elements::<E::G2Affine>(tau_g2, compressed_output)?;
        if after_g2[0] != E::G2Affine::prime_subgroup_generator() {
            return Err(VerificationError::InvalidGenerator(ElementType::TauG2).into());
        }
        let g1_check = (after_g1[0], after_g1[1]);
        let g2_check = (after_g2[0], after_g2[1]);

        // Check TauG1 -> TauG2
        check_same_ratio::<E>(
            &(before_g1[1], after_g1[1]),
            tau_g2_check,
            "Before-After: Tau [1] G1<>G2",
        )?;
        for (before, after, check) in &[
            (in_alpha_g1, alpha_g1, alpha_g2_check),
            (in_beta_g1, beta_g1, beta_g2_check),
        ] {
            before.par_read_batch_preallocated(&mut before_g1, compressed_input)?;
            after.par_read_batch_preallocated(&mut after_g1, compressed_output)?;
            check_same_ratio::<E>(
                &(before_g1[0], after_g1[0]),
                check,
                "Before-After: Alpha[0] G1<>G2",
            )?;
        }

        let before_beta_g2 = in_beta_g2.read_element::<E::G2Affine>(compressed_input)?;
        let after_beta_g2 = beta_g2.read_element::<E::G2Affine>(compressed_output)?;
        check_same_ratio::<E>(
            &(before_g1[0], after_g1[0]),
            &(before_beta_g2, after_beta_g2),
            "Before-After: Other[0] G1<>G2",
        )?;

        (g1_check, g2_check)
    };

    // preallocate 2 vectors per batch
    // Ensure that the pairs are created correctly (we do this in chunks!)
    // load `batch_size` chunks on each iteration and perform the transformation
    iter_chunk(&parameters, |start, end| {
        rayon::scope(|t| {
            t.spawn(|_| {
                let mut g1 = vec![E::G1Affine::zero(); parameters.batch_size];
                check_power_ratios::<E>(
                    (tau_g1, compressed_output),
                    (start, end),
                    &mut g1,
                    &g2_check,
                )
                .expect("could not check ratios for Tau G1");
            });

            if start < parameters.powers_length {
                // if the `end` would be out of bounds, then just process until
                // the end (this is necessary in case the last batch would try to
                // process more elements than available)
                let end = if start + parameters.batch_size > parameters.powers_length {
                    parameters.powers_length
                } else {
                    end
                };

                rayon::scope(|t| {
                    t.spawn(|_| {
                        let mut g2 = vec![E::G2Affine::zero(); parameters.batch_size];
                        check_power_ratios_g2::<E>(
                            (tau_g2, compressed_output),
                            (start, end),
                            &mut g2,
                            &g1_check,
                        )
                        .expect("could not check ratios for Tau G2");
                    });

                    t.spawn(|_| {
                        let mut g1 = vec![E::G1Affine::zero(); parameters.batch_size];
                        check_power_ratios::<E>(
                            (alpha_g1, compressed_output),
                            (start, end),
                            &mut g1,
                            &g2_check,
                        )
                        .expect("could not check ratios for Alpha G1");
                    });

                    t.spawn(|_| {
                        let mut g1 = vec![E::G1Affine::zero(); parameters.batch_size];
                        check_power_ratios::<E>(
                            (beta_g1, compressed_output),
                            (start, end),
                            &mut g1,
                            &g2_check,
                        )
                        .expect("could not check ratios for Beta G1");
                    });
                });
            }
        });

        Ok(())
    })
}

/// Serializes all the provided elements to the output buffer
#[allow(unused)]
pub fn serialize<E: PairingEngine>(
    elements: AccumulatorElementsRef<E>,
    output: &mut [u8],
    compressed: UseCompression,
    parameters: &CeremonyParams<E>,
) -> Result<()> {
    let (in_tau_g1, in_tau_g2, in_alpha_g1, in_beta_g1, in_beta_g2) = elements;
    let (tau_g1, tau_g2, alpha_g1, beta_g1, beta_g2) = split_mut(output, parameters, compressed);

    tau_g1.write_batch(&in_tau_g1, compressed)?;
    tau_g2.write_batch(&in_tau_g2, compressed)?;
    alpha_g1.write_batch(&in_alpha_g1, compressed)?;
    beta_g1.write_batch(&in_beta_g1, compressed)?;
    beta_g2.write_element(in_beta_g2, compressed)?;

    Ok(())
}

/// warning, only use this on machines which have enough memory to load
/// the accumulator in memory
pub fn deserialize<E: PairingEngine>(
    input: &[u8],
    compressed: UseCompression,
    parameters: &CeremonyParams<E>,
) -> Result<AccumulatorElements<E>> {
    // get an immutable reference to the input chunks
    let (in_tau_g1, in_tau_g2, in_alpha_g1, in_beta_g1, in_beta_g2) =
        split(&input, parameters, compressed);

    // deserialize each part of the buffer separately
    let tau_g1 = in_tau_g1.par_read_batch(compressed)?;
    let tau_g2 = in_tau_g2.par_read_batch(compressed)?;
    let alpha_g1 = in_alpha_g1.par_read_batch(compressed)?;
    let beta_g1 = in_beta_g1.par_read_batch(compressed)?;
    let beta_g2 = in_beta_g2.read_element(compressed)?;

    Ok((tau_g1, tau_g2, alpha_g1, beta_g1, beta_g2))
}

/// Reads an input buffer and a secret key **which must be destroyed after this function is executed**.
pub fn decompress<E: PairingEngine>(
    input: &[u8],
    output: &mut [u8],
    parameters: &CeremonyParams<E>,
) -> Result<()> {
    let compressed_input = UseCompression::Yes;
    let compressed_output = UseCompression::No;
    // get an immutable reference to the compressed input chunks
    let (in_tau_g1, in_tau_g2, in_alpha_g1, in_beta_g1, in_beta_g2) =
        split(&input, parameters, compressed_input);

    // get mutable refs to the decompressed outputs
    let (tau_g1, tau_g2, alpha_g1, beta_g1, beta_g2) =
        split_mut(output, parameters, compressed_output);

    // decompress beta_g2 for the first chunk
    {
        // get the compressed element
        let beta_g2_el = in_beta_g2.read_element::<E::G2Affine>(compressed_input)?;
        // write it back decompressed
        beta_g2.write_element(&beta_g2_el, compressed_output)?;
    }

    // load `batch_size` chunks on each iteration and decompress them
    iter_chunk(&parameters, |start, end| {
        // decompress each element
        rayon::scope(|t| {
            t.spawn(|_| {
                decompress_buffer::<E::G1Affine>(tau_g1, in_tau_g1, (start, end))
                    .expect("could not decompress the TauG1 elements")
            });
            if start < parameters.powers_length {
                // if the `end` would be out of bounds, then just process until
                // the end (this is necessary in case the last batch would try to
                // process more elements than available)
                let end = if start + parameters.batch_size > parameters.powers_length {
                    parameters.powers_length
                } else {
                    end
                };

                rayon::scope(|t| {
                    t.spawn(|_| {
                        decompress_buffer::<E::G2Affine>(tau_g2, in_tau_g2, (start, end))
                            .expect("could not decompress the TauG2 elements")
                    });
                    t.spawn(|_| {
                        decompress_buffer::<E::G1Affine>(alpha_g1, in_alpha_g1, (start, end))
                            .expect("could not decompress the AlphaG1 elements")
                    });
                    t.spawn(|_| {
                        decompress_buffer::<E::G1Affine>(beta_g1, in_beta_g1, (start, end))
                            .expect("could not decompress the BetaG1 elements")
                    });
                });
            }
        });

        Ok(())
    })
}

/// Reads an input buffer and a secret key **which must be destroyed after this function is executed**.
/// It then generates 2^(N+1) -1 powers of tau (tau is stored inside the secret key).
/// Finally, each group element read from the input is multiplied by the corresponding power of tau depending
/// on its index and maybe some extra coefficient, and is written to the output buffer.
pub fn contribute<E: PairingEngine>(
    input: (&[u8], UseCompression),
    output: (&mut [u8], UseCompression),
    key: &PrivateKey<E>,
    parameters: &CeremonyParams<E>,
) -> Result<()> {
    let (input, compressed_input) = (input.0, input.1);
    let (output, compressed_output) = (output.0, output.1);
    // get an immutable reference to the input chunks
    let (in_tau_g1, in_tau_g2, in_alpha_g1, in_beta_g1, in_beta_g2) =
        split(&input, parameters, compressed_input);

    // get mutable refs to the outputs
    let (tau_g1, tau_g2, alpha_g1, beta_g1, beta_g2) =
        split_mut(output, parameters, compressed_output);

    // write beta_g2 for the first chunk
    {
        // get the element
        let mut beta_g2_el = in_beta_g2.read_element::<E::G2Affine>(compressed_input)?;
        // multiply it by the key's beta
        beta_g2_el = beta_g2_el.mul(key.beta).into_affine();
        // write it back
        beta_g2.write_element(&beta_g2_el, compressed_output)?;
    }

    // load `batch_size` chunks on each iteration and perform the transformation
    iter_chunk(&parameters, |start, end| {
        // generate powers from `start` to `end` (e.g. [0,4) then [4, 8) etc.)
        let powers = generate_powers_of_tau::<E>(&key.tau, start, end);

        // raise each element from the input buffer to the powers of tau
        // and write the updated value (without allocating) to the
        // output buffer
        rayon::scope(|t| {
            t.spawn(|_| {
                apply_powers::<E::G1Affine>(
                    (tau_g1, compressed_output),
                    (in_tau_g1, compressed_input),
                    (start, end),
                    &powers,
                    None,
                )
                .expect("could not apply powers of tau to the TauG1 elements")
            });
            if start < parameters.powers_length {
                // if the `end` would be out of bounds, then just process until
                // the end (this is necessary in case the last batch would try to
                // process more elements than available)
                let end = if start + parameters.batch_size > parameters.powers_length {
                    parameters.powers_length
                } else {
                    end
                };

                rayon::scope(|t| {
                    t.spawn(|_| {
                        apply_powers::<E::G2Affine>(
                            (tau_g2, compressed_output),
                            (in_tau_g2, compressed_input),
                            (start, end),
                            &powers,
                            None,
                        )
                        .expect("could not apply powers of tau to the TauG2 elements")
                    });
                    t.spawn(|_| {
                        apply_powers::<E::G1Affine>(
                            (alpha_g1, compressed_output),
                            (in_alpha_g1, compressed_input),
                            (start, end),
                            &powers,
                            Some(&key.alpha),
                        )
                        .expect("could not apply powers of tau to the AlphaG1 elements")
                    });
                    t.spawn(|_| {
                        apply_powers::<E::G1Affine>(
                            (beta_g1, compressed_output),
                            (in_beta_g1, compressed_input),
                            (start, end),
                            &powers,
                            Some(&key.beta),
                        )
                        .expect("could not apply powers of tau to the BetaG1 elements")
                    });
                });
            }
        });

        Ok(())
    })
}

/// Takes a compressed input buffer and decompresses it
fn decompress_buffer<C: AffineCurve>(
    output: &mut [u8],
    input: &[u8],
    (start, end): (usize, usize),
) -> Result<()> {
    let in_size = buffer_size::<C>(UseCompression::Yes);
    let out_size = buffer_size::<C>(UseCompression::No);
    // read the compressed input
    let elements =
        input[start * in_size..end * in_size].par_read_batch::<C>(UseCompression::Yes)?;
    // write it back uncompressed
    output[start * out_size..end * out_size].write_batch(&elements, UseCompression::No)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use test_helpers::random_point_vec;
    use zexe_algebra::bls12_377::Bls12_377;

    #[test]
    fn test_decompress_buffer() {
        test_decompress_buffer_curve::<<Bls12_377 as PairingEngine>::G1Affine>();
        test_decompress_buffer_curve::<<Bls12_377 as PairingEngine>::G2Affine>();
    }

    fn test_decompress_buffer_curve<C: AffineCurve>() {
        // generate some random points
        let mut rng = thread_rng();
        let num_els = 10;
        let elements: Vec<C> = random_point_vec(num_els, &mut rng);
        // write them as compressed
        let len = num_els * buffer_size::<C>(UseCompression::Yes);
        let mut input = vec![0; len];
        input.write_batch(&elements, UseCompression::Yes).unwrap();

        // allocate the decompressed buffer
        let len = num_els * buffer_size::<C>(UseCompression::No);
        let mut out = vec![0; len];
        // perform the decompression
        decompress_buffer::<C>(&mut out, &input, (0, num_els)).unwrap();
        let deserialized = out.par_read_batch::<C>(UseCompression::No).unwrap();
        // ensure they match
        assert_eq!(deserialized, elements);
    }
}

/// Takes a buffer, reads the group elements in it, exponentiates them to the
/// provided `powers` and maybe to the `coeff`, and then writes them back
fn apply_powers<C: AffineCurve>(
    (output, output_compressed): Output,
    (input, input_compressed): Input,
    (start, end): (usize, usize),
    powers: &[C::ScalarField],
    coeff: Option<&C::ScalarField>,
) -> Result<()> {
    let in_size = buffer_size::<C>(input_compressed);
    let out_size = buffer_size::<C>(output_compressed);
    // read the input
    let mut elements =
        &mut input[start * in_size..end * in_size].par_read_batch::<C>(input_compressed)?;
    // calculate the powers
    batch_exp(&mut elements, &powers[..end - start], coeff)?;
    // write back
    output[start * out_size..end * out_size].write_batch(&elements, output_compressed)?;

    Ok(())
}

/// Splits the full buffer in 5 non overlapping mutable slice.
/// Each slice corresponds to the group elements in the following order
/// [TauG1, TauG2, AlphaG1, BetaG1, BetaG2]
fn split_mut<'a, E: PairingEngine>(
    buf: &'a mut [u8],
    parameters: &'a CeremonyParams<E>,
    compressed: UseCompression,
) -> SplitBufMut<'a> {
    let g1_els = parameters.powers_g1_length;
    let other = parameters.powers_length;
    let g1_size = buffer_size::<E::G1Affine>(compressed);
    let g2_size = buffer_size::<E::G2Affine>(compressed);

    // leave the first 64 bytes for the hash
    let (_, others) = buf.split_at_mut(parameters.hash_size);
    let (tau_g1, others) = others.split_at_mut(g1_size * g1_els);
    let (tau_g2, others) = others.split_at_mut(g2_size * other);
    let (alpha_g1, others) = others.split_at_mut(g1_size * other);
    let (beta_g1, beta_g2) = others.split_at_mut(g1_size * other);
    // we take up to g2_size for beta_g2, since there might be other
    // elements after it at the end of the buffer
    (tau_g1, tau_g2, alpha_g1, beta_g1, &mut beta_g2[0..g2_size])
}

/// Splits the full buffer in 5 non overlapping immutable slice.
/// Each slice corresponds to the group elements in the following order
/// [TauG1, TauG2, AlphaG1, BetaG1, BetaG2]
fn split<'a, E: PairingEngine>(
    buf: &'a [u8],
    parameters: &CeremonyParams<E>,
    compressed: UseCompression,
) -> SplitBuf<'a> {
    let g1_els = parameters.powers_g1_length;
    let other = parameters.powers_length;
    let g1_size = buffer_size::<E::G1Affine>(compressed);
    let g2_size = buffer_size::<E::G2Affine>(compressed);

    let (_, others) = buf.split_at(parameters.hash_size);
    let (tau_g1, others) = others.split_at(g1_size * g1_els);
    let (tau_g2, others) = others.split_at(g2_size * other);
    let (alpha_g1, others) = others.split_at(g1_size * other);
    let (beta_g1, beta_g2) = others.split_at(g1_size * other);
    // we take up to g2_size for beta_g2, since there might be other
    // elements after it at the end of the buffer
    (tau_g1, tau_g2, alpha_g1, beta_g1, &beta_g2[0..g2_size])
}
