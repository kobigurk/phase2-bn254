use crate::{buffer_size, Result, UseCompression};
use std::io::Read;
use zexe_algebra::AffineCurve;

#[cfg(feature = "parallel")]
use rayon::prelude::*;
use zexe_fft::cfg_chunks;

/// Used for reading 1 group element from a serialized buffer
pub trait Deserializer {
    /// Reads 1 compressed or uncompressed element
    fn read_element<G: AffineCurve>(&mut self, compression: UseCompression) -> Result<G>;

    /// Reads 1 compressed or uncompressed element to a pre-allocated element
    fn read_element_preallocated<G: AffineCurve>(
        &mut self,
        el: &mut G,
        compression: UseCompression,
    ) -> Result<()>;
}

// TODO: Implement this for `Read`
pub trait BatchDeserializer {
    /// Reads multiple elements from the buffer
    fn read_batch<G: AffineCurve>(&self, compression: UseCompression) -> Result<Vec<G>>;

    /// Reads multiple elements from the buffer to a preallocated array of Group elements
    fn read_batch_preallocated<G: AffineCurve>(
        &self,
        elements: &mut [G],
        compression: UseCompression,
    ) -> Result<()>;
}

impl<R: Read> Deserializer for R {
    fn read_element<G: AffineCurve>(&mut self, compression: UseCompression) -> Result<G> {
        Ok(match compression {
            UseCompression::Yes => G::deserialize(self)?,
            UseCompression::No => G::deserialize_uncompressed(self)?,
        })
    }

    fn read_element_preallocated<G: AffineCurve>(
        &mut self,
        el: &mut G,
        compression: UseCompression,
    ) -> Result<()> {
        *el = self.read_element(compression)?;
        Ok(())
    }
}

// We implement this for slices so that the consumer does not need to write the `&mut slice.as_ref()`
// boilerplate in each call. This should have no performance overhead
impl Deserializer for [u8] {
    fn read_element<G: AffineCurve>(&mut self, compression: UseCompression) -> Result<G> {
        (&*self).read_element(compression)
    }

    fn read_element_preallocated<G: AffineCurve>(
        &mut self,
        el: &mut G,
        compression: UseCompression,
    ) -> Result<()> {
        *el = self.read_element(compression)?;
        Ok(())
    }
}

// We implement this specifically for slices so that we can take advantage
// of parallel iterators
impl BatchDeserializer for [u8] {
    fn read_batch<G: AffineCurve>(&self, compression: UseCompression) -> Result<Vec<G>> {
        let size = buffer_size::<G>(compression);
        cfg_chunks!(&*self, size)
            .map(|mut buf| buf.read_element(compression))
            .collect::<Result<Vec<_>>>()
    }

    fn read_batch_preallocated<G: AffineCurve>(
        &self,
        elements: &mut [G],
        compression: UseCompression,
    ) -> Result<()> {
        let size = buffer_size::<G>(compression);
        cfg_chunks!(&*self, size)
            .zip(elements)
            .map(|(mut buf, el)| buf.read_element_preallocated(el, compression))
            .collect::<Result<Vec<_>>>()?;
        Ok(())
    }
}
