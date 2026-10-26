# Windows catalogue and SS recovery parity

Sync the recent macOS catalogue explanation and SS rotation behavior into the
existing Rust/Tauri Windows implementation. Preserve Windows physical carrier
ownership, cancellation, same-city intent, and chain-last/direct-return policy.

Also address valid API data being discarded on cache-write failure, incomplete
SS candidate coverage, sub-1280 dual-stack WG MTUs, and missing worker-side TLS
hostname recovery for pure-IP destinations.

This stage is source and tests only. No installer, installed-app replacement,
account/device mutation, network interruption, sleep, signing or publication.
Mac-only native-family fallback, multihop and PQ are not Windows live features.
