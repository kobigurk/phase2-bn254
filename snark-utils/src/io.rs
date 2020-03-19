//! Utilities for writing and reading group elements to buffers in parallel
use crate::{Result, UseCompression};
use zexe_algebra::AffineCurve;

pub fn buffer_size<C: AffineCurve>(compression: UseCompression) -> usize {
    C::buffer_size()
        * if compression == UseCompression::No {
            2
        } else {
            1
        }
}

#[cfg(feature = "parallel")]
use rayon::prelude::*;
use zexe_fft::{cfg_chunks, cfg_chunks_mut, cfg_iter_mut};

/// Used for reading 1 group element from a serialized buffer
pub trait Deserializer {
    /// Reads 1 compressed or uncompressed element
    fn read_element<G: AffineCurve>(&self, compression: UseCompression) -> Result<G>;

    /// Reads 1 compressed or uncompressed element to a pre-allocated element
    fn read_element_preallocated<G: AffineCurve>(
        &self,
        el: &mut G,
        compression: UseCompression,
    ) -> Result<()>;

    /// Reads multiple elements from the buffer
    fn read_batch<G: AffineCurve>(&self, compression: UseCompression) -> Result<Vec<G>>;

    /// Reads multiple elements from the buffer to a preallocated array of Group elements
    fn read_batch_preallocated<G: AffineCurve>(
        &self,
        elements: &mut [G],
        compression: UseCompression,
    ) -> Result<()>;
}

impl Deserializer for [u8] {
    fn read_element<G: AffineCurve>(&self, compression: UseCompression) -> Result<G> {
        Ok(match compression {
            UseCompression::Yes => G::deserialize(self, &mut [])?,
            UseCompression::No => G::deserialize_uncompressed(self)?,
        })
    }

    fn read_element_preallocated<G: AffineCurve>(
        &self,
        el: &mut G,
        compression: UseCompression,
    ) -> Result<()> {
        *el = match compression {
            UseCompression::Yes => G::deserialize(self, &mut [])?,
            UseCompression::No => G::deserialize_uncompressed(self)?,
        };
        Ok(())
    }

    fn read_batch<G: AffineCurve>(&self, compression: UseCompression) -> Result<Vec<G>> {
        let size = buffer_size::<G>(compression);
        cfg_chunks!(self, size)
            .map(|buf| buf.read_element(compression))
            .collect()
    }

    fn read_batch_preallocated<G: AffineCurve>(
        &self,
        elements: &mut [G],
        compression: UseCompression,
    ) -> Result<()> {
        let element_size = buffer_size::<G>(compression);
        cfg_iter_mut!(elements)
            .enumerate()
            .map(|(i, el)| {
                Ok(self[i * element_size..(i + 1) * element_size]
                    .read_element_preallocated(el, compression)?)
            })
            .collect()
    }
}

/// Used for writing elements to a buffer directly
pub trait Serializer {
    /// Initializes the buffer with the provided element
    fn init_element(
        &mut self,
        element: &impl AffineCurve,
        element_size: usize,
        compression: UseCompression,
    ) -> Result<()>;

    /// Writes a compressed or uncompressed element to the buffer
    fn write_element(
        &mut self,
        element: &impl AffineCurve,
        compression: UseCompression,
    ) -> Result<()>;

    /// Writes multiple elements to the buffer. Internally calls `write_element`
    fn write_batch<G: AffineCurve>(
        &mut self,
        elements: &[G],
        compression: UseCompression,
    ) -> Result<()>;
}

impl Serializer for [u8] {
    fn write_element(
        &mut self,
        element: &impl AffineCurve,
        compression: UseCompression,
    ) -> Result<()> {
        match compression {
            UseCompression::Yes => element.serialize(&[], self)?,
            UseCompression::No => element.serialize_uncompressed(self)?,
        };
        Ok(())
    }

    fn init_element(
        &mut self,
        element: &impl AffineCurve,
        element_size: usize,
        compression: UseCompression,
    ) -> Result<()> {
        // writes to the buffer in `element_size` chunks
        // note: it might be the case that running this in parallel incurs
        // performance overhead instead of gain if the buffer's length is not
        // big enough
        cfg_chunks_mut!(self, element_size)
            .map(|buf| {
                (&mut buf[0..element_size]).write_element(element, compression)?;
                Ok(())
            })
            .collect::<Result<()>>()
    }

    /// Writes multiple elements to the buffer. Internally calls `write_element`
    fn write_batch<G: AffineCurve>(
        &mut self,
        elements: &[G],
        compression: UseCompression,
    ) -> Result<()> {
        let element_size = buffer_size::<G>(compression);
        cfg_chunks_mut!(self, element_size)
            .zip(elements)
            .map(|(buf, element)| {
                (&mut buf[0..element_size]).write_element(element, compression)?;
                Ok(())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use test_helpers::random_point_vec;
    use zexe_algebra::bls12_377::{G1Affine, G2Affine};

    #[test]
    fn read_write_single() {
        read_write_single_element::<G1Affine>(UseCompression::No);
        read_write_single_element::<G1Affine>(UseCompression::Yes);
        read_write_single_element::<G2Affine>(UseCompression::No);
        read_write_single_element::<G2Affine>(UseCompression::Yes);
    }

    #[test]
    fn read_write_single_preallocated() {
        read_write_single_element_preallocated::<G1Affine>(UseCompression::No);
        read_write_single_element_preallocated::<G1Affine>(UseCompression::Yes);
        read_write_single_element_preallocated::<G2Affine>(UseCompression::No);
        read_write_single_element_preallocated::<G2Affine>(UseCompression::Yes);
    }

    #[test]
    fn read_write_batch() {
        read_write_batch_element::<G1Affine>(UseCompression::No);
        read_write_batch_element::<G1Affine>(UseCompression::Yes);
        read_write_batch_element::<G2Affine>(UseCompression::No);
        read_write_batch_element::<G2Affine>(UseCompression::Yes);
    }

    #[test]
    fn read_write_batch_preallocated() {
        read_write_batch_element_preallocated::<G1Affine>(UseCompression::No);
        read_write_batch_element_preallocated::<G1Affine>(UseCompression::Yes);
        read_write_batch_element_preallocated::<G2Affine>(UseCompression::No);
        read_write_batch_element_preallocated::<G2Affine>(UseCompression::Yes);
    }

    fn read_write_single_element<E: AffineCurve>(compression: UseCompression) {
        // uncompressed buffers are twice the size
        let len = if compression == UseCompression::Yes {
            E::buffer_size()
        } else {
            2 * E::buffer_size()
        };
        let el = E::prime_subgroup_generator();
        let mut buf = vec![0; len];
        // assert that the deserialized version is the same as the serialized
        buf.write_element(&el, compression).unwrap();
        let deserialized: E = buf.read_element(compression).unwrap();
        assert_eq!(el, deserialized);
    }

    fn read_write_single_element_preallocated<E: AffineCurve>(compression: UseCompression) {
        // uncompressed buffers are twice the size
        let len = if compression == UseCompression::Yes {
            E::buffer_size()
        } else {
            2 * E::buffer_size()
        };
        let mut prealloc = E::zero();
        let el = E::prime_subgroup_generator();
        let mut buf = vec![0; len];
        // assert that the deserialized version is the same as the serialized
        buf.write_element(&el, compression).unwrap();
        buf.read_element_preallocated(&mut prealloc, compression)
            .unwrap();
        assert_eq!(el, prealloc);
    }

    fn read_write_batch_element<E: AffineCurve>(compression: UseCompression) {
        // generate a vector of 10 elements
        let num_els = 10;
        let mut rng = thread_rng();
        let elements: Vec<E> = random_point_vec(num_els, &mut rng);
        let len = buffer_size::<E>(compression) * num_els;
        let mut buf = vec![0; len];
        buf.write_batch(&elements, compression).unwrap();
        let deserialized1: Vec<E> = buf.read_batch(compression).unwrap();
        let deserialized2: Vec<E> = buf.read_batch(compression).unwrap();
        assert_eq!(elements, deserialized1);
        assert_eq!(elements, deserialized2);
    }

    fn read_write_batch_element_preallocated<E: AffineCurve>(compression: UseCompression) {
        // generate a vector of 10 elements
        let num_els = 10;
        let mut rng = thread_rng();
        let elements: Vec<E> = random_point_vec(num_els, &mut rng);
        // generate another preallocated vector
        let len = buffer_size::<E>(compression) * num_els;
        let mut buf = vec![0; len];
        buf.write_batch(&elements, compression).unwrap();
        let mut prealloc: Vec<E> = random_point_vec(num_els, &mut rng);
        let mut prealloc2: Vec<E> = random_point_vec(num_els, &mut rng);
        buf.read_batch_preallocated(&mut prealloc, compression)
            .unwrap();
        buf.read_batch_preallocated(&mut prealloc2, compression)
            .unwrap();
        assert_eq!(elements, prealloc);
        assert_eq!(elements, prealloc2);
    }
}
