# Powers of Tau

## Original story

This is a [multi-party computation](https://en.wikipedia.org/wiki/Secure_multi-party_computation) (MPC) ceremony which constructs partial zk-SNARK parameters for _all_ circuits up to a depth of 2<sup>21</sup>. It works by taking a step that is performed by all zk-SNARK MPCs and performing it in just one single ceremony. This makes individual zk-SNARK MPCs much cheaper and allows them to scale to practically unbounded numbers of participants.

This protocol is described in a [forthcoming paper](https://eprint.iacr.org/2017/1050). It produces parameters for an adaptation of [Jens Groth's 2016 pairing-based proving system](https://eprint.iacr.org/2016/260) using the [BLS12-381](https://github.com/ebfull/pairing/tree/master/src/bls12_381) elliptic curve construction. The security proof relies on a randomness beacon being applied at the end of the ceremony.

## Contributions

Extended to support Ethereum's BN256 curve and made it easier to change size of the ceremony. In addition proof generation process can be done in memory constrained environments now. Benchmark is around `1.3 Gb` of memory and `3 hours` for a `2^26` power of tau on BN256 curve on my personal laptop

## Instructions

Instructions for a planned ceremony will be posted when everything is tested and finalized.

---
## To run the ceremony on your laptop:

1. Preparation:

```
rustup update # tested on rustup 1.17.0
cargo build
```

2. Put `response` file from the previous ceremony to root directory.
3. To generate `new_challenge` run:

```
cargo run --release --bin verify_transform_constrained # this will generate new_challenge from response file
```

4. Backup old files and replace `challenge` file:

```
mv challenge challenge_old
mv response response_old
mv new_challenge challenge
```

5. Run ceremony:

```
cargo run --release --bin compute_constrained # generate response file
```

Put your hash from output response to private gist (example: https://gist.github.com/skywinder/c35ab03c66c6b200b33ea2f388a6df89)

6. Reboot laptop to clean up toxic waste.

7. Save `response` file and give it to the next participant.

## Recommendations from original ceremony

Participants of the ceremony sample some randomness, perform a computation, and then destroy the randomness. **Only one participant needs to do this successfully to ensure the final parameters are secure.** In order to see that this randomness is truly destroyed, participants may take various kinds of precautions:

* putting the machine in a Faraday cage
* rebooting the machine afterwards
* rebooting the machine afterwards and disconnecting RAM
* destroying the machine afterwards
* running the software on secure hardware
* not connecting the hardware to any networks
* using multiple machines and randomly picking the result of one of them to use
* using different code than what we have provided
* using a secure operating system
* using an operating system that nobody would expect you to use (Rust can compile to Mac OS X and Windows)
* using an unusual Rust toolchain or [alternate rust compiler](https://github.com/thepowersgang/mrustc)
* lots of other ideas we can't think of

It is totally up to the participants. In general, participants should beware of side-channel attacks and assume that remnants of the randomness will be in RAM after the computation has finished.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
