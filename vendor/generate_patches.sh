#!/bin/bash

set -e
set -o pipefail

VENDOR_DIR="vendor"

pushd $VENDOR_DIR > /dev/null

next_patch_path() {
    local base_path="$1"
    local path="$base_path"
    local counter=1

    while [[ -e "$path" ]]; do
        path="${base_path%.patch}${counter}.patch"
        ((counter++))
    done

    printf '%s\n' "$path"
}

# For every submodule, cd into it directory and generate patches
# don't forget to skip the patches directory
for submodule_dir in */ ; do
    [[ "$submodule_dir" == "patches/" ]] && continue

    submodule_name=$(basename "$submodule_dir")

    pushd "$submodule_name" > /dev/null

    if git diff --quiet; then
        echo "Skipping patch for submodule $submodule_name because diff is empty"
        popd > /dev/null
        continue
    fi

    # Generate patch and save it to patches directory
    patch_path=$(next_patch_path "../patches/${submodule_name}_dep.patch")

    echo "Generating patch for submodule $submodule_name and saving it to $patch_path"
    git diff > "$patch_path"

    popd > /dev/null
done

popd > /dev/null
