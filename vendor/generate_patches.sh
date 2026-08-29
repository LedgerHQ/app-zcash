#!/bin/bash
#
# Regenerate the Ledger patches from the committed vendored trees. Run from the
# repository root.
#
# Each patch is the diff between a crate's pinned base and its vendored tree, so
# regenerating means fetching that base again — the vendored directories carry no
# .git of their own, and a `git diff` taken inside one answers about the
# application repository instead, which reports nothing at all once the vendored
# change is committed.
#
# Every patch written here is verified by reapplying it to a fresh base and
# comparing the result to the vendored tree. A patch that does not reproduce what
# it claims to describe is worse than no patch, so that check is fatal.

set -euo pipefail

VENDOR_DIR="vendor"
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# shellcheck source=vendor/pinned_deps.sh
source "$SCRIPT_DIR/pinned_deps.sh"

WORK_DIR=$(mktemp -d -t vendor-patches.XXXXXX)
trap 'rm -rf "$WORK_DIR"' EXIT

# Keep the provenance notes a patch already carries: they record things the pins
# cannot, such as an upstream fix backported into the base.
existing_header() {
    local patch_file=$1

    [[ -f "$patch_file" ]] || return 0
    awk '/^#/ { print; next } { exit }' "$patch_file"
}

default_header() {
    local name=$1 kind=$2 coord=$3

    printf '# Ledger delta for the vendored `%s` crate.\n#\n' "$name"
    case "$kind" in
        crates) printf '# Base: crates.io package %s %s\n' "$name" "$coord" ;;
        git) printf '# Base: %s at %s\n' "${coord%% *}" "${coord##* }" ;;
    esac
    case "$kind" in
        crates) printf '# Apply from %s/%s with: patch -p1 -E < ../patches/%s_dep.patch\n' "$VENDOR_DIR" "$name" "$name" ;;
        git) printf '# Apply from %s/%s with: git apply ../patches/%s_dep.patch\n' "$VENDOR_DIR" "$name" "$name" ;;
    esac
    printf '#\n# Regenerate with vendor/generate_patches.sh, which also verifies the result.\n#\n'
}

for entry in "${VENDORED_DEPS[@]}"; do
    IFS='|' read -r name kind coord <<< "$entry"

    vendored="$VENDOR_DIR/$name"
    patch_file="$SCRIPT_DIR/patches/${name}_dep.patch"

    if [[ ! -d "$vendored" ]]; then
        echo "Skipping $name: $vendored is not present."
        continue
    fi

    echo "Fetching $name base ($kind $coord)..."
    base="$WORK_DIR/$name/a"
    mirror="$WORK_DIR/$name/b"
    mkdir -p "$WORK_DIR/$name"
    materialize_base "$name" "$kind" "$coord" "$base"

    # Diffed as sibling directories named a and b so the patch carries the a/ and
    # b/ prefixes that `patch -p1` and `git apply` both expect.
    cp -R "$vendored" "$mirror"
    for excluded in "${BASE_DIFF_EXCLUDES[@]}"; do
        rm -rf "$base/$excluded" "$mirror/$excluded"
    done

    candidate="$WORK_DIR/$name.patch"
    {
        header=$(existing_header "$patch_file")
        if [[ -n "$header" ]]; then
            printf '%s\n' "$header"
        else
            default_header "$name" "$kind" "$coord"
        fi
        # diff exits 1 when the trees differ, which is the expected case here.
        # Its output is then made independent of when and where it ran: the
        # mtimes it prints and the flags it echoes back carry no information a
        # reader or `patch` needs, and leaving them in would make every
        # regeneration show up as a change to all six patches.
        (cd "$WORK_DIR/$name" && diff -ruN "${DIFF_EXCLUDE_ARGS[@]}" a b) |
            sed -E -e 's/^(---|\+\+\+) ([^[:space:]]+)[[:space:]].*$/\1 \2/' \
                -e 's/^diff -ruN .* (a\/[^[:space:]]+) (b\/[^[:space:]]+)$/diff -ruN \1 \2/' ||
            true
    } > "$candidate"

    if ! grep -qv '^#' "$candidate"; then
        echo "Skipping $name: vendored tree is identical to its base."
        continue
    fi

    # Reapply to a fresh base and require the result to match the vendored tree.
    check="$WORK_DIR/$name/check"
    materialize_base "$name" "$kind" "$coord" "$check"
    apply_dep_patch "$kind" "$check" "$candidate"

    if ! diff -r "${DIFF_EXCLUDE_ARGS[@]}" "$check" "$vendored" > "$WORK_DIR/$name.verify" 2>&1; then
        echo "REFUSING to write patches/${name}_dep.patch: reapplying it does not reproduce $vendored" >&2
        sed 's/^/  /' "$WORK_DIR/$name.verify" >&2
        exit 1
    fi

    cp "$candidate" "$patch_file"
    echo "Wrote patches/${name}_dep.patch (verified by reapplying it to a fresh base)"
done
