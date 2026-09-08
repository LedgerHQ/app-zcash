#!/bin/bash
#
# Where each vendored crate's pristine base comes from, and how a patch is
# applied to it. `update_deps.sh` and `generate_patches.sh` both source this
# file, so a pin cannot be right in one and stale in the other.
#
# Two kinds of base, because the patches were authored against different things:
#
#   crates  The published crates.io package. Base of every patch carrying a
#           `# Base: crates.io package ...` header. Those are `diff -ruN` output
#           and need `patch -p1 -E`; without `-E` a deletion leaves a zero-byte
#           file behind instead of removing it, and the result stops matching the
#           vendored tree.
#   git     A clone at a pinned ref, patched with `git apply`. Only
#           rust-secp256k1 needs this: its vendored tree keeps the sibling
#           `secp256k1-sys` crate, which the published package does not carry.
#
# Fields: name|kind|coordinate. For `crates` the coordinate is the version; for
# `git` it is the clone URL and the ref, separated by a space.

VENDORED_DEPS=(
    "orchard|crates|0.15.5"
    "radium|crates|0.7.0"
    "reddsa|crates|0.5.1"
    "sapling-crypto|crates|0.7.0"
    "spin|crates|0.9.8"
    "rust-secp256k1|git|https://github.com/rust-bitcoin/rust-secp256k1.git secp256k1-0.29.1"
)

# Present in one tree and not the other for reasons that have nothing to do with
# the Ledger delta: `.cargo-ok` and `.claude` are left in a vendored directory by
# tooling, `.git` by a clone. A patch must neither create nor delete them.
BASE_DIFF_EXCLUDES=(.git .cargo-ok .claude)

# Prebuilt as an array rather than produced by a function: macOS ships bash 3.2,
# which has no `mapfile` to read a function's output back into one.
DIFF_EXCLUDE_ARGS=()
for _excluded in "${BASE_DIFF_EXCLUDES[@]}"; do
    DIFF_EXCLUDE_ARGS+=("--exclude=$_excluded")
done
unset _excluded

# Fetch a crate's unmodified base into $dest, which must not already exist.
materialize_base() {
    local name=$1 kind=$2 coord=$3 dest=$4

    case "$kind" in
        crates)
            local url="https://static.crates.io/crates/$name/$name-$coord.crate"
            local archive
            archive=$(mktemp -t "$name.crate.XXXXXX")
            curl -fsSL "$url" -o "$archive"
            mkdir -p "$dest"
            tar xzf "$archive" -C "$dest" --strip-components=1
            rm -f "$archive"
            ;;
        git)
            local url=${coord%% *} ref=${coord##* }
            git clone --quiet "$url" "$dest"
            git -C "$dest" checkout --quiet "$ref"
            ;;
        *)
            echo "Unknown base kind '$kind' for $name" >&2
            return 1
            ;;
    esac
}

# Apply a patch to a materialized base, with the tool that patch was written for.
apply_dep_patch() {
    local kind=$1 dir=$2 patch_file=$3

    case "$kind" in
        crates) (cd "$dir" && patch -p1 -E --silent < "$patch_file") ;;
        git) git -C "$dir" apply "$patch_file" ;;
        *)
            echo "Unknown base kind '$kind'" >&2
            return 1
            ;;
    esac
}