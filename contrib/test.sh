#!/bin/sh -ex

FEATURES="hashes global-context lowmemory rand rand-std recovery serde"

cargo --version
rustc --version

# Make all cargo invocations verbose
export CARGO_TERM_VERBOSE=true

# Defaults / sanity checks
cargo build --all
cargo test --all

if [ "$DO_FEATURE_MATRIX" = true ]; then
    cargo build --all --no-default-features
    #This doesn't work but probably should --andrew
    #cargo test --all --no-default-features

    # All features
    cargo build --all --no-default-features --features="$FEATURES"
    cargo test --all --features="$FEATURES"
    # Single features
    for feature in ${FEATURES}
    do
        cargo build --all --no-default-features --features="$feature"
        cargo test --all --features="$feature"
    done

    # Other combos
    RUSTFLAGS='--cfg=rust_secp_fuzz' cargo test --all
    RUSTFLAGS='--cfg=rust_secp_fuzz' cargo test --all --features="$FEATURES"
    cargo test --all --features="rand rand-std"
    cargo test --all --features="rand serde"

    cargo test --all --all-features
    RUSTFLAGS='--cfg=rust_secp_fuzz' RUSTDOCFLAGS='--cfg=rust_secp_fuzz' cargo test --all --all-features
fi

# Docs
if [ "$DO_DOCS" = true ]; then
    cargo doc --all --features="$FEATURES"
fi

# Webassembly stuff
if [ "$DO_WASM" = true ]; then
    clang --version
    wasm-pack build
    wasm-pack test --node;
fi

# Address Sanitizer
if [ "$DO_ASAN" = true ]; then
    clang --version
    cargo clean
    CC='clang -fsanitize=address -fno-omit-frame-pointer'                                        \
    RUSTFLAGS='-Zsanitizer=address -Clinker=clang -Cforce-frame-pointers=yes'                    \
    ASAN_OPTIONS='detect_leaks=1 detect_invalid_pointer_pairs=1 detect_stack_use_after_return=1' \
    cargo test --lib --all --features="$FEATURES" -Zbuild-std --target x86_64-unknown-linux-gnu
fi

# Lint if told to
if [ "$DO_LINT" = true ]
then
    (
        cargo fmt --all -- --check
    )
fi

exit 0
