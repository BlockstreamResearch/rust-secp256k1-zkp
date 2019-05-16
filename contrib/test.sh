#!/bin/bash

if [ -z "$1" ]; then
  echo This test script runs the workspace tests and the -sys tests with the
  echo serde feature enabled. This is necessary because you can not test
  echo features on the workspace level. The script also checks if the files are
  echo rustfmt\'d.
  echo
  echo "ERROR: \$1 parameter must be the workspace directory"
  exit 1
fi
DIR=$1

shopt -s globstar

(
    cd "$DIR"
    set -e
    cargo test
    (
        cd secp256k1-zkp-sys
        cargo test --features serde
    )
    rustfmt --check -- **/*.rs
)

if [ $? -ne 0 ]; then
    echo ERROR: $0 failed
    exit 1
fi

