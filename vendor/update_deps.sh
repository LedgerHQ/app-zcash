#!/bin/bash

set -euo pipefail

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

list_vendor_dirs() {
    local dir
    local nullglob_was_set=0

    if shopt -q nullglob; then
        nullglob_was_set=1
    else
        shopt -s nullglob
    fi

    for dir in "$VENDOR_DIR"/*/; do
        dir="${dir%/}"

        [[ "$(basename "$dir")" == "patches" ]] && continue

        printf '%s\n' "$dir"
    done

    if [[ "$nullglob_was_set" -eq 0 ]]; then
        shopt -u nullglob
    fi
}

should_keep_git_dirs() {
    local choice

    read -r -p "Keep .git directories in vendored repos? [y/N] " choice
    [[ "$choice" =~ ^([yY]|[yY][eE][sS])$ ]]
}

should_remove_existing_vendor_dirs() {
    local choice

    read -r -p "Remove existing directories in $VENDOR_DIR before cloning? [y/N] " choice
    [[ "$choice" =~ ^([yY]|[yY][eE][sS])$ ]]
}

# Create dir if it doesn't exist
mkdir -p "$VENDOR_DIR"

mapfile -t vendor_repo_dirs < <(list_vendor_dirs)

if [[ "${#vendor_repo_dirs[@]}" -gt 0 ]]; then
    echo "Existing directories in $VENDOR_DIR:"
    printf ' - %s\n' "${vendor_repo_dirs[@]#"$VENDOR_DIR"/}"

    if should_remove_existing_vendor_dirs; then
        echo "Removing directories from $VENDOR_DIR:"
        printf ' - %s\n' "${vendor_repo_dirs[@]#"$VENDOR_DIR"/}"
        for dest_dir in "${vendor_repo_dirs[@]}"; do
            rm -rf "$dest_dir"
        done
    else
        echo "Keeping existing directories in $VENDOR_DIR"
    fi
fi

clone_repo "https://github.com/zcash/orchard.git"               "8de172448be10f3a470f9ac83198dc8a185986ad" "$VENDOR_DIR/orchard"
clone_repo "https://github.com/ferrilab/radium.git"             "3f27e0d827338aee919213fd071b99819a1b9fff" "$VENDOR_DIR/radium"
clone_repo "https://github.com/rust-bitcoin/rust-secp256k1.git" "secp256k1-0.29.1"                         "$VENDOR_DIR/rust-secp256k1"
clone_repo "https://github.com/zcash/sapling-crypto.git"        "8186b407b47b595a2ea4f04c73d59fdd83bd401f" "$VENDOR_DIR/sapling-crypto"
clone_repo "https://github.com/zesterer/spin-rs.git"            "502c9dca17c99762184095c9d64c0aedd1db97ff" "$VENDOR_DIR/spin"
clone_repo "https://github.com/ZcashFoundation/reddsa.git"      "0.5.1"                                    "$VENDOR_DIR/reddsa"

pushd "$VENDOR_DIR" > /dev/null

# Patch submodule deps
# For every patch file in deps/patches, apply it to the corresponding submodule
shopt -s nullglob
mapfile -t patch_files < <(printf '%s\n' patches/*.patch | sort -V)

for patch_file in "${patch_files[@]}"; do
    patch_filename=$(basename "$patch_file")

    if [[ "$patch_filename" =~ ^(.+)_dep([0-9]+)?\.patch$ ]]; then
        submodule_name="${BASH_REMATCH[1]}"
    else
        echo "Skipping patch with unexpected name: $patch_file"
        continue
    fi

    echo "Applying patch $patch_file to submodule $submodule_name"
    # Change to submodule directory
    pushd "$submodule_name" > /dev/null
    # Apply the patch
    git apply "../$patch_file"
    # Return to original directory
    popd > /dev/null
done

popd > /dev/null

mapfile -t vendor_repo_dirs < <(list_vendor_dirs)

if [[ "${#vendor_repo_dirs[@]}" -gt 0 ]]; then
    echo "Vendored repos:"
    printf ' - %s\n' "${vendor_repo_dirs[@]#"$VENDOR_DIR"/}"
fi

if should_keep_git_dirs; then
    echo "Keeping .git directories in vendored repos"
else
    echo "Removing .git directories from:"
    printf ' - %s\n' "${vendor_repo_dirs[@]#"$VENDOR_DIR"/}"
    for dest_dir in "${vendor_repo_dirs[@]}"; do
        echo "Removing .git directory from $dest_dir"
        rm -rf "$dest_dir/.git"
    done
fi
