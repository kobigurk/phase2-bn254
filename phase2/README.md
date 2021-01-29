# phase2 [![Crates.io](https://img.shields.io/crates/v/phase2.svg)](https://crates.io/crates/phase2) #

This library is still under development.

## WebAssembly how-to

Build wasm package using `wasm-pack build --release -- --no-default-features --features wasm`

this will generate `./pkg` directory with wasm file and js bindings. After that you 
can use this package in your browser application like so:

```js
async function main() {
    const phase2 = await import("./pkg/phase2.js")
    let data = await fetch('params')
    data = await data.arrayBuffer()
    data = new Uint8Array(data)
    console.log('Source params', data)
    const result = phase2.contribute(data)
    console.log('Updated params', result)
    // upload updated params
}

main().catch(console.error)
``` 

## Service Worker 

Some differences are required to implement the module in a service worker.

Build wasm package using `wasm-pack build --target no-modules --release -- --no-default-features --features wasm`

Service workers can't do a dynamic import, as above. Instead load the shims using:
```js
self.importScripts(./pkg/phase2.js);
```

This will make wasm_bindgen available to the service worker. 
Declare the `contribute` function like this:
```js
const { contribute } = wasm_bindgen;
``` 
Load the wasm binary like this:
```js
await wasm_bindgen('./pkg/phase2_bg.wasm');
```
and run `contribute` like this:
```js
const result = contribute(sourceParams, ...);
```

## [Documentation](https://docs.rs/phase2/)

## Security Warnings

This library does not make any guarantees about constant-time operations, memory access patterns, or resistance to side-channel attacks. To see possible measures to protect the secret data generated during the ceremony, see the [Powers of Tau readme][../powersoftau/README.md].

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
