use gumdrop::Options;
use powersoftau::{
    batched_accumulator::*,
    cli_common::{curve_from_str, proving_system_from_str, CurveKind, ProvingSystem},
    parameters::*,
    utils::log_2,
};

use bellman_ce::domain::{EvaluationDomain, Point};
use bellman_ce::pairing::{bn256::Bn256, CurveAffine, CurveProjective, Engine};
use bellman_ce::worker::Worker;

use std::fs::OpenOptions;
use std::io::{BufWriter, Write};

use memmap::*;

#[derive(Debug, Options, Clone)]
struct PreparePhase2Opts {
    help: bool,
    #[options(
        help = "the response file which will be processed for the specialization (phase 2) of the setup"
    )]
    response_fname: String,
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
    #[options(help = "the size of batches to process", default = "256")]
    pub batch_size: usize,
    #[options(
        help = "the circuit power (circuit size will be 2^{power})",
        default = "21"
    )]
    pub power: usize,
}

fn main() {
    let opts = PreparePhase2Opts::parse_args_default_or_exit();

    let parameters = CeremonyParams::<Bn256>::new(opts.power, opts.batch_size);

    prepare_phase2(&opts.response_fname, &parameters);
}

fn prepare_phase2<E: Engine + Sync>(response_filename: &str, parameters: &CeremonyParams<E>) {
    // Try to load response file from disk.
    let reader = OpenOptions::new()
        .read(true)
        .open(response_filename)
        .expect("unable open response file in this directory");
    let response_readable_map = unsafe {
        MmapOptions::new()
            .map(&reader)
            .expect("unable to create a memory map for input")
    };

    let current_accumulator = BatchedAccumulator::deserialize(
        &response_readable_map,
        CheckForCorrectness::Yes,
        UseCompression::Yes,
        &parameters,
    )
    .expect("unable to read uncompressed accumulator");

    let worker = &Worker::new();

    // Create the parameters for various 2^m circuit depths.
    let max_degree = log_2(current_accumulator.tau_powers_g2.len() as u64);
    for m in 0..=max_degree {
        let paramname = format!("phase1radix2m{}", m);
        println!("Creating {}", paramname);

        let degree = 1 << m;

        let mut g1_coeffs = EvaluationDomain::from_coeffs(
            current_accumulator.tau_powers_g1[0..degree]
                .iter()
                .map(|e| Point(e.into_projective()))
                .collect(),
        )
        .unwrap();

        let mut g2_coeffs = EvaluationDomain::from_coeffs(
            current_accumulator.tau_powers_g2[0..degree]
                .iter()
                .map(|e| Point(e.into_projective()))
                .collect(),
        )
        .unwrap();

        let mut g1_alpha_coeffs = EvaluationDomain::from_coeffs(
            current_accumulator.alpha_tau_powers_g1[0..degree]
                .iter()
                .map(|e| Point(e.into_projective()))
                .collect(),
        )
        .unwrap();

        let mut g1_beta_coeffs = EvaluationDomain::from_coeffs(
            current_accumulator.beta_tau_powers_g1[0..degree]
                .iter()
                .map(|e| Point(e.into_projective()))
                .collect(),
        )
        .unwrap();

        // This converts all of the elements into Lagrange coefficients
        // for later construction of interpolation polynomials
        g1_coeffs.ifft(&worker);
        g2_coeffs.ifft(&worker);
        g1_alpha_coeffs.ifft(&worker);
        g1_beta_coeffs.ifft(&worker);

        let g1_coeffs = g1_coeffs.into_coeffs();
        let g2_coeffs = g2_coeffs.into_coeffs();
        let g1_alpha_coeffs = g1_alpha_coeffs.into_coeffs();
        let g1_beta_coeffs = g1_beta_coeffs.into_coeffs();

        assert_eq!(g1_coeffs.len(), degree);
        assert_eq!(g2_coeffs.len(), degree);
        assert_eq!(g1_alpha_coeffs.len(), degree);
        assert_eq!(g1_beta_coeffs.len(), degree);

        // Remove the Point() wrappers

        let mut g1_coeffs = g1_coeffs.into_iter().map(|e| e.0).collect::<Vec<_>>();

        let mut g2_coeffs = g2_coeffs.into_iter().map(|e| e.0).collect::<Vec<_>>();

        let mut g1_alpha_coeffs = g1_alpha_coeffs.into_iter().map(|e| e.0).collect::<Vec<_>>();

        let mut g1_beta_coeffs = g1_beta_coeffs.into_iter().map(|e| e.0).collect::<Vec<_>>();

        // Batch normalize
        <E as Engine>::G1::batch_normalization(&mut g1_coeffs);
        <E as Engine>::G2::batch_normalization(&mut g2_coeffs);
        <E as Engine>::G1::batch_normalization(&mut g1_alpha_coeffs);
        <E as Engine>::G1::batch_normalization(&mut g1_beta_coeffs);

        // H query of Groth16 needs...
        // x^i * (x^m - 1) for i in 0..=(m-2) a.k.a.
        // x^(i + m) - x^i for i in 0..=(m-2)
        // for radix2 evaluation domains
        let mut h = Vec::with_capacity(degree - 1);
        for i in 0..(degree - 1) {
            let mut tmp = current_accumulator.tau_powers_g1[i + degree].into_projective();
            let mut tmp2 = current_accumulator.tau_powers_g1[i].into_projective();
            tmp2.negate();
            tmp.add_assign(&tmp2);

            h.push(tmp);
        }

        // Batch normalize this as well
        <E as Engine>::G1::batch_normalization(&mut h);

        // Create the parameter file
        let writer = OpenOptions::new()
            .read(false)
            .write(true)
            .create_new(true)
            .open(paramname)
            .expect("unable to create parameter file in this directory");

        let mut writer = BufWriter::new(writer);

        // Write alpha (in g1)
        // Needed by verifier for e(alpha, beta)
        // Needed by prover for A and C elements of proof
        writer
            .write_all(
                current_accumulator.alpha_tau_powers_g1[0]
                    .into_uncompressed()
                    .as_ref(),
            )
            .unwrap();

        // Write beta (in g1)
        // Needed by prover for C element of proof
        writer
            .write_all(
                current_accumulator.beta_tau_powers_g1[0]
                    .into_uncompressed()
                    .as_ref(),
            )
            .unwrap();

        // Write beta (in g2)
        // Needed by verifier for e(alpha, beta)
        // Needed by prover for B element of proof
        writer
            .write_all(current_accumulator.beta_g2.into_uncompressed().as_ref())
            .unwrap();

        // Lagrange coefficients in G1 (for constructing
        // LC/IC queries and precomputing polynomials for A)
        for coeff in g1_coeffs.clone() {
            // Was normalized earlier in parallel
            let coeff = coeff.into_affine();

            writer
                .write_all(coeff.into_uncompressed().as_ref())
                .unwrap();
        }

        // Lagrange coefficients in G2 (for precomputing
        // polynomials for B)
        for coeff in g2_coeffs {
            // Was normalized earlier in parallel
            let coeff = coeff.into_affine();

            writer
                .write_all(coeff.into_uncompressed().as_ref())
                .unwrap();
        }

        // Lagrange coefficients in G1 with alpha (for
        // LC/IC queries)
        for coeff in g1_alpha_coeffs {
            // Was normalized earlier in parallel
            let coeff = coeff.into_affine();

            writer
                .write_all(coeff.into_uncompressed().as_ref())
                .unwrap();
        }

        // Lagrange coefficients in G1 with beta (for
        // LC/IC queries)
        for coeff in g1_beta_coeffs {
            // Was normalized earlier in parallel
            let coeff = coeff.into_affine();

            writer
                .write_all(coeff.into_uncompressed().as_ref())
                .unwrap();
        }

        // Bases for H polynomial computation
        for coeff in h {
            // Was normalized earlier in parallel
            let coeff = coeff.into_affine();

            writer
                .write_all(coeff.into_uncompressed().as_ref())
                .unwrap();
        }
    }
}
