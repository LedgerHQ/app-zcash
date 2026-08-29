#!/bin/bash
#
# Rebuild the vendored crates from their pinned bases and reapply the Ledger
# patches. Run from the repository root.
#
# The patches are the record of every local modification, several of which are
# security fixes, so a base that a patch cannot apply to is a hard failure here
# rather than something to skip past.

set -euo pipefail

VENDOR_DIR="vendor"
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# shellcheck source=vendor/pinned_deps.sh
source "$SCRIPT_DIR/pinned_deps.sh"

should_remove_existing_vendor_dirs() {
    local choice

    read -r -p "Remove existing directories in $VENDOR_DIR before fetching? [y/N] " choice
    [[ "$choice" =~ ^([yY]|[yY][eE][sS])$ ]]
}

should_keep_git_dirs() {
    local choice

    read -r -p "Keep .git directories in git-sourced vendored repos? [y/N] " choice
    [[ "$choice" =~ ^([yY]|[yY][eE][sS])$ ]]
}

mkdir -p "$VENDOR_DIR"

existing=()
for entry in "${VENDORED_DEPS[@]}"; do
    IFS='|' read -r name _ _ <<< "$entry"
    [[ -d "$VENDOR_DIR/$name" ]] && existing+=("$name")
done

remove_existing=0
if [[ "${#existing[@]}" -gt 0 ]]; then
    echo "Existing directories in $VENDOR_DIR:"
    printf ' - %s\n' "${existing[@]}"

    if should_remove_existing_vendor_dirs; then
        remove_existing=1
    else
        echo "Keeping existing directories; they will be left untouched."
    fi
fi

git_sourced=()

for entry in "${VENDORED_DEPS[@]}"; do
    IFS='|' read -r name kind coord <<< "$entry"

    dest="$VENDOR_DIR/$name"
    patch_file="$SCRIPT_DIR/patches/${name}_dep.patch"

    if [[ -d "$dest" ]]; then
        if [[ "$remove_existing" -eq 1 ]]; then
            rm -rf "$dest"
        else
            echo "Skipping $name: directory already present."
            [[ "$kind" == "git" ]] && git_sourced+=("$dest")
            continue
        fi
    fi

    echo "Fetching $name base ($kind $coord)..."
    materialize_base "$name" "$kind" "$coord" "$dest"

    if [[ ! -f "$patch_file" ]]; then
        echo "No patch for $name; leaving the base as fetched."
        [[ "$kind" == "git" ]] && git_sourced+=("$dest")
        continue
    fi

    echo "Applying patches/${name}_dep.patch to $name..."
    apply_dep_patch "$kind" "$dest" "$patch_file"

    [[ "$kind" == "git" ]] && git_sourced+=("$dest")
done

if [[ "${#git_sourced[@]}" -gt 0 ]] && ! should_keep_git_dirs; then
    for dest in "${git_sourced[@]}"; do
        echo "Removing .git directory from $dest"
        rm -rf "$dest/.git"
    done
fi

echo
echo "Vendored crates rebuilt. Confirm the result matches what is committed with:"
echo "  git status --porcelain $VENDOR_DIR"
echo "Anything reported there is a difference between the patches and the"
echo "committed vendored source, and one of the two is wrong."
