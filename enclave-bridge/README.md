# pallet-enclave-bridge

Please note this pallet has a different [license](./LICENSE) than the rest of this repository: MS-RSL

A pallet for [Integritee](https://integritee.network) that acts as a bridge between L1(integritee network) and L2(enclaves). 
* indirect-invocation proxy for calls to the confidential state transition function executed in SGX enclaves off-chain.

More documentation available at:
* High-level: https://www.integritee.network/for-developer
* In-depth: https://book.integritee.network/

## Test

Run all unit tests with 

```
cargo test --all
```

