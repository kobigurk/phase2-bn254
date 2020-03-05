# Groth16 Specialization

Distributed generation of parameters for for Phase 2 of [BGM17](https://eprint.iacr.org/2017/1050). 

This library does not provide any binaries, since the circuit has to be compiled with it. An example of how this is done can be seen in the [E2E tests](https://github.com/celo-org/snark-setup/blob/canonical-serialize/phase2/tests/mpc.rs#L40-L43)


The library provides a wrapper around Groth16's Parameters which allows performing consistency checks over the contributions of each participant.