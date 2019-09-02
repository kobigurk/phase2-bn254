extern crate rand;
extern crate crossbeam;
extern crate num_cpus;
extern crate blake2;
extern crate generic_array;
extern crate typenum;
extern crate byteorder;
extern crate bellman;

use self::bellman::pairing::ff::{Field, PrimeField};
use self::byteorder::{ReadBytesExt, BigEndian};
use self::rand::{SeedableRng, Rng, Rand};
use self::rand::chacha::ChaChaRng;
use self::bellman::pairing::bn256::{Bn256};
use self::bellman::pairing::*;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};
use self::generic_array::GenericArray;
use self::typenum::consts::U64;
use self::blake2::{Blake2b, Digest};
use std::fmt;

use crate::parameters::*;
use crate::keypair::*;
use crate::utils::*;

#[derive(Clone)]
pub struct Bn256CeremonyParameters {

}

impl PowersOfTauParameters for Bn256CeremonyParameters {
    const REQUIRED_POWER: usize = 25; // generate to have roughly 2 million constraints

    // This ceremony is based on the BN256 elliptic curve construction.
    const G1_UNCOMPRESSED_BYTE_SIZE: usize = 64;
    const G2_UNCOMPRESSED_BYTE_SIZE: usize = 128;
    const G1_COMPRESSED_BYTE_SIZE: usize = 32;
    const G2_COMPRESSED_BYTE_SIZE: usize = 64;
}
