#!/bin/sh -ex

FEATURES="hashes global-context lowmemory use-rand rand-std recovery use-serde"

# Use toolchain if explicitly specified
if [ -n "$TOOLCHAIN" ]
then
    alias cargo="cargo +$TOOLCHAIN"
fi

cargo --version
rustc --version

# Defaults / sanity checks
cargo build --verbose
cargo test --verbose

if [ "$DO_FEATURE_MATRIX" = true ]; then
    cargo build --verbose --no-default-features
    #This doesn't work but probably should --andrew
    #cargo test --verbose --no-default-features

    # All features
    cargo build --verbose --no-default-features --features="$FEATURES"
    cargo test --verbose --features="$FEATURES"
    # Single features
    for feature in ${FEATURES}
    do
        cargo build --verbose --no-default-features --features="$feature"
        cargo test --verbose --features="$feature"
    done

    # Other combos 
    cargo test --no-run --verbose --features="fuzztarget"
    cargo test --no-run --verbose --features="fuzztarget recovery"
    cargo test --verbose --features="use-rand rand-std"
    cargo test --verbose --features="use-rand use-serde"
fi

# Docs
if [ "$DO_DOCS" = true ]; then
    cargo doc --verbose --features="$FEATURES"
fi

# Webassembly stuff
if [ "$DO_WASM" = true ]; then
    clang --version &&
    printf '\n[lib]\ncrate-type = ["cdylib", "rlib"]\n' >> Cargo.toml &&
    CC=clang-9 wasm-pack build &&
    CC=clang-9 wasm-pack test --node;
fi

# Address Sanitizer
if [ "$DO_ASAN" = true ]; then
    cargo clean
    CC='clang -fsanitize=address -fno-omit-frame-pointer'                                        \
    RUSTFLAGS='-Zsanitizer=address -Clinker=clang -Cforce-frame-pointers=yes'                    \
    ASAN_OPTIONS='detect_leaks=1 detect_invalid_pointer_pairs=1 detect_stack_use_after_return=1' \
    cargo test --lib --verbose --features="$FEATURES" -Zbuild-std --target x86_64-unknown-linux-gnu
fi

# Bench
if [ "$DO_BENCH" = true ]; then
    cargo bench --features="unstable"
fi

