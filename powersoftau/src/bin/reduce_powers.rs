use bellman_ce::pairing::{bn256::Bn256, Engine};
use gumdrop::Options;
use memmap::MmapOptions;
use powersoftau::{
    batched_accumulator::BatchedAccumulator,
    cli_common::{curve_from_str, proving_system_from_str, CurveKind, ProvingSystem},
    parameters::{CeremonyParams, CheckForCorrectness, UseCompression},
    utils::{calculate_hash, print_hash, reduced_hash},
};
use std::{fs::OpenOptions, io::Write};

#[derive(Debug, Options, Clone)]
struct ReducePowersOpts {
    help: bool,
    #[options(help = "the challenge file which contains all the calculated powers of tau")]
    challenge_fname: String,
    #[options(help = "the challenge file which will contain the extracted poweres of tau")]
    reduced_challenge_fname: String,
    #[options(help = "the size of batches to process", default = "256")]
    pub batch_size: usize,
    #[options(help = "the circuit power used for calculating the original challenge file")]
    pub original_circuit_power: usize,
    #[options(help = "the number of powers which will be extracted")]
    pub reduced_circuit_power: usize,
    #[options(
        help = "the elliptic curve to use",
        default = "bn256",
        parse(try_from_str = "curve_from_str")
    )]
    pub curve_kind: CurveKind,
    #[options(
        help = "the proving system to use",
        default = "groth16",
        parse(try_from_str = "proving_system_from_str")
    )]
    pub proving_system: ProvingSystem,
}

fn main() {
    let opts = ReducePowersOpts::parse_args_default_or_exit();
    let parameters = CeremonyParams::<Bn256>::new(opts.reduced_circuit_power, opts.batch_size);

    reduce_powers(
        &opts.challenge_fname,
        &opts.reduced_challenge_fname,
        opts.original_circuit_power,
        &parameters,
    );
}

fn reduce_powers<E: Engine + Sync>(
    challenge_filename: &str,
    reduced_challenge_filename: &str,
    original_circuit_power: usize,
    parameters: &CeremonyParams<E>,
) {
    // Try to load the challenge from disk.
    let reader = OpenOptions::new()
        .read(true)
        .open(challenge_filename)
        .expect("unable to open challenge in this directory");
    let challenge_readable_map = unsafe {
        MmapOptions::new()
            .map(&reader)
            .expect("unable to create a memory map for input")
    };

    let current_accumulator = BatchedAccumulator::deserialize(
        &challenge_readable_map,
        CheckForCorrectness::Yes,
        UseCompression::No,
        &parameters,
    )
    .expect("unable to read compressed accumulator");

    let mut reduced_accumulator = BatchedAccumulator::empty(&parameters);
    reduced_accumulator.tau_powers_g1 =
        current_accumulator.tau_powers_g1[..parameters.powers_g1_length].to_vec();
    reduced_accumulator.tau_powers_g2 =
        current_accumulator.tau_powers_g2[..parameters.powers_length].to_vec();
    reduced_accumulator.alpha_tau_powers_g1 =
        current_accumulator.alpha_tau_powers_g1[..parameters.powers_length].to_vec();
    reduced_accumulator.beta_tau_powers_g1 =
        current_accumulator.beta_tau_powers_g1[..parameters.powers_length].to_vec();
    reduced_accumulator.beta_g2 = current_accumulator.beta_g2;

    let writer = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(reduced_challenge_filename)
        .expect("unable to create the reduced challenge in this directory");

    // Recomputation stips the public key and uses hashing to link with the previous contibution after decompression
    writer
        .set_len(parameters.accumulator_size as u64)
        .expect("must make output file large enough");

    let mut writable_map = unsafe {
        MmapOptions::new()
            .map_mut(&writer)
            .expect("unable to create a memory map for output")
    };

    let hash = reduced_hash(original_circuit_power as u8, parameters.size as u8);
    (&mut writable_map[0..])
        .write_all(hash.as_slice())
        .expect("unable to write a default hash to mmap");
    writable_map
        .flush()
        .expect("unable to write reduced hash to the reduced_challenge");

    println!("Reduced hash for a reduced challenge:");
    print_hash(&hash);

    reduced_accumulator
        .serialize(&mut writable_map, UseCompression::No, &parameters)
        .unwrap();

    // Get the hash of the contribution, so the user can compare later
    let output_readonly = writable_map
        .make_read_only()
        .expect("must make a map readonly");
    let contribution_hash = calculate_hash(&output_readonly);

    println!("Reduced contribution is formed with a hash:");
    print_hash(&contribution_hash);
    println!("Wrote a reduced accumulator to `./challenge`");
}
