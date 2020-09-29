# Groth16 Specialization

Distributed generation of parameters for for Phase 2 of [BGM17](https://eprint.iacr.org/2017/1050). 

This library does not provide any binaries, since the circuit has to be compiled with it. An example of how this is done can be seen in the [E2E tests](https://github.com/celo-org/snark-setup/blob/canonical-serialize/phase2/tests/mpc.rs#L40-L43)


The library provides a wrapper around Groth16's Parameters which allows performing consistency checks over the contributions of each participant.

## License

This work is licensed under either of the following licenses, at your discretion.

- Apache License Version 2.0 (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you,
as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
