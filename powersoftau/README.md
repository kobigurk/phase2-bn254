# Powers of Tau

Distributed generation of powers of tau for Phase 1 of [BGM17](https://eprint.iacr.org/2017/1050). 

Also contains a binary which converts the Powers of Tau to Lagrange Coefficients and produces the H query for the Groth16 SNARK.

- Utilizes [Zexe's algebra crate](https://github.com/scipr-lab/zexe), meaning we support all available curves:
    - BW6-761
    - Bls 12-381
    - Bls 12-377
    - ...
- Memory footprint can be configured by adjusting `batch-size` via CLI and via environment variable [`RAYON_NUM_THREADS`](https://github.com/rayon-rs/rayon/blob/master/FAQ.md#how-many-threads-will-rayon-spawn).

You can see an E2E demo with 3 participants and the beacon at the end by running `test.sh`.

## CLI Guide

### Powers of Tau

Coordinators run:
1. `new` to create a new accumulator
1. `verify-and-transform` after receiving a contribution to the previous challenge, to produce a new challenge for the next contribution
1. `beacon` at the end of the ceremony (optional, as the security proof [does not require it](https://electriccoin.co/blog/reinforcing-the-security-of-the-sapling-mpc/))

Users should only care about the `contribute` option.

```
$ ./powersoftau --help
Usage: ./powersoftau [OPTIONS]

Optional arguments:
  -h, --help
  -c, --curve-kind CURVE-KIND
                     the elliptic curve to use (default: bls12_381)
  -p, --proving-system PROVING-SYSTEM
                     the proving system to use (default: groth16)
  -b, --batch-size BATCH-SIZE
                     the size of batches to process (default: 256)
  -P, --power POWER  the circuit power (circuit size will be 2^{power}) (default: 21)

Available commands:

  new                   creates a new challenge for the ceremony
  contribute            contribute to ceremony by producing a response to a challenge (or create a new challenge if this is the first contribution)
  beacon                contribute randomness via a random beacon (e.g. a bitcoin block header hash)
  verify-and-transform  verify the contributions so far and generate a new challenge
```

### Prepare Phase 2

This binary will only be run by the coordinator after Phase 1 has been executed.
Note that the parameters produced are **only for the Groth16 SNARK**.

```
./prepare_phase2 --help
Usage: ./prepare_phase2 [OPTIONS]

Optional arguments:
  -h, --help
  -p, --phase2-fname PHASE2-FNAME
                             the file which will contain the FFT coefficients processed for Phase 2 of the setup
  -r, --response-fname RESPONSE-FNAME
                             the response file which will be processed for the specialization (phase 2) of the setup
  -c, --curve-kind CURVE-KIND
                             the elliptic curve to use (default: bls12_377)
  -P, --proving-system PROVING-SYSTEM
                             the proving system to use (default: groth16)
  -b, --batch-size BATCH-SIZE
                             the size of batches to process (default: 256)
  --power POWER              the number of powers used for phase 1 (circuit size will be 2^{power}) (default: 21)
  --phase2-size PHASE2-SIZE  the size of the phase 2 circuit (default: 21
```

## Disclaimer

This is a fork of a [fork](https://github.com/kobigurk/phase2-bn254/) of a [fork](https://github.com/matter-labs/powersoftau). Credits go to the corresponding authors for producing the original implementations.
