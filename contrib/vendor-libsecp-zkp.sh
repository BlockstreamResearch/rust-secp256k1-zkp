#!/bin/bash
set -e


if [ -z "$1" ]; then
  echo "\$1 parameter must be the rust-secp256k1-zkp-sys depend directory"
  exit 1
fi

PARENT_DIR=$1
DIR=secp256k1-zkp

while true; do
    read -r -p "$PARENT_DIR/$DIR will be deleted [yn]: " yn
    case $yn in
        [Yy]* ) break;;
        [Nn]* ) exit;;
        * ) echo "Please answer yes or no.";;
    esac
done

cd "$PARENT_DIR"
rm -rf "$DIR"
git clone git@github.com:ElementsProject/secp256k1-zkp.git
cd "$DIR"
HEAD=$(git rev-parse HEAD)
cd ..
echo "\# This file was automatically created by contrib/$0" > ./secp256k1-zkp-HEAD-revision.txt
echo "$HEAD" >> ./secp256k1-zkp-HEAD-revision.txt

find "$DIR" -not -path '*/\.*' -type f -print0 | xargs -0 sed -i '/^#include/! s/secp256k1_/secp256k1_zkp_/g'
# TODO: can be removed once 496c5b43b lands in secp-zkp
find "$DIR" -not -path '*/\.*' -type f -print0 | xargs -0 sed -i 's/^const int CURVE_B/static const int CURVE_B/g'
