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
#   git     A clone at a pinned ref, patched with `git apply`, for a vendored
#           tree that needs files the published package does not carry. No
#           current pin uses it.
#
# Fields: name|kind|coordinate|sha256. For `crates` the coordinate is the version
# and the sha256 is that of the downloaded `.crate` archive, the checksum the
# crates.io index publishes for that version; a download that does not match is
# refused. For `git` the coordinate is the clone URL and the ref, separated by a
# space, and the ref pins the content, so the sha256 field is left empty.

VENDORED_DEPS=(
    "orchard|crates|0.16.0|4ae7ceb7b5387bd76cf3c0712f57708795c925cecf097036cedb60b5c3706e8f"
    "radium|crates|0.7.0|dc33ff2d4973d518d823d61aa239014831e521c75da58e3df4840d3f47749d09"
    "reddsa|crates|0.6.1|4a70b6dbd7b3277cbd4d89ee750a30bebab3b9951ee4e166ce15c00975fe410f"
    "sapling-crypto|crates|0.9.0|4a2cbdcfeef20006adf72699cd466f21fe349674277cc05d3fc9b7302db7b182"
    "spin|crates|0.9.8|6980e8d7511241f8acf4aebddbb1ff938df5eebe98691418c4468d0b72a96a67"
    "secp256k1|crates|0.33.1|d7f404a8dab7a7a5a631e741d8699aa9c8e1d689fc26ccf897c7187565490b69"
    "secp256k1-sys|crates|0.14.1|f6b2992d4a3cd244539a7d5d0966aadbe5ca7fb868a5d7e38c29499b9e709bbd"
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

# The sha256 of a file, with whichever tool the platform ships.
file_sha256() {
    if command -v sha256sum >/dev/null; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

# Fetch a crate's unmodified base into $dest, which must not already exist.
materialize_base() {
    local name=$1 kind=$2 coord=$3 sha256=$4 dest=$5

    case "$kind" in
        crates)
            local url="https://static.crates.io/crates/$name/$name-$coord.crate"
            local archive actual
            archive=$(mktemp -t "$name.crate.XXXXXX")
            curl -fsSL "$url" -o "$archive"
            actual=$(file_sha256 "$archive")
            if [[ "$actual" != "$sha256" ]]; then
                echo "REFUSING $name $coord: archive sha256 $actual, pinned $sha256" >&2
                rm -f "$archive"
                return 1
            fi
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