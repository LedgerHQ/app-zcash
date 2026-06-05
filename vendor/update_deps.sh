#!/bin/bash

set -euo pipefail

KEEP_GIT_DIRS=${KEEP_GIT_DIRS:-0}
VENDOR_DIR="vendor"

function clone_repo() {
    local repo_url=$1
    local commit_hash=$2
    local dest_dir="$3"

    if [ -d "$dest_dir" ]; then
        echo "Directory $dest_dir already exists. Skipping clone."
    else
        echo "Cloning $repo_url into $dest_dir..."
        git clone "$repo_url" "$dest_dir" > /dev/null
        pushd "$dest_dir" > /dev/null
        git checkout $commit_hash > /dev/null 2>&1
        popd > /dev/null
    fi

}

pushd $VENDOR_DIR > /dev/null
rm -rf orchard/ radium/ rust-secp256k1/ sapling-crypto/ spin/
popd > /dev/null

# Create dir if it doesn't exist
mkdir -p "$VENDOR_DIR"

clone_repo "https://github.com/zcash/orchard.git"               "8de172448be10f3a470f9ac83198dc8a185986ad" "$VENDOR_DIR/orchard"
clone_repo "https://github.com/ferrilab/radium.git"             "3f27e0d827338aee919213fd071b99819a1b9fff" "$VENDOR_DIR/radium"
clone_repo "https://github.com/rust-bitcoin/rust-secp256k1.git" "1a1fc57fb99a5a42b996d3cdde5c48fda3797709" "$VENDOR_DIR/rust-secp256k1"
clone_repo "https://github.com/zcash/sapling-crypto.git"        "8186b407b47b595a2ea4f04c73d59fdd83bd401f" "$VENDOR_DIR/sapling-crypto"
clone_repo "https://github.com/zesterer/spin-rs.git"            "502c9dca17c99762184095c9d64c0aedd1db97ff" "$VENDOR_DIR/spin"

pushd "$VENDOR_DIR" > /dev/null

# Patch submodule deps
# For every patch file in deps/patches, apply it to the corresponding submodule
for patch_file in patches/*.patch; do
    # Extract submodule name from patch file name
    patch_filename=$(basename "$patch_file")
    submodule_name="${patch_filename%_dep.patch}"
    echo "Applying patch $patch_file to submodule $submodule_name"
    # Change to submodule directory
    pushd "$submodule_name" > /dev/null
    # Apply the patch
    git apply "../$patch_file"
    # Return to original directory
    popd > /dev/null
done

popd > /dev/null

for dest_dir in "$VENDOR_DIR"/orchard "$VENDOR_DIR"/radium "$VENDOR_DIR"/rust-secp256k1 "$VENDOR_DIR"/sapling-crypto "$VENDOR_DIR"/spin ; do
    if [ "$KEEP_GIT_DIRS" -eq 0 ]; then
        echo "Removing .git directory from $dest_dir"
        rm -rf "$dest_dir/.git"
    fi
done
