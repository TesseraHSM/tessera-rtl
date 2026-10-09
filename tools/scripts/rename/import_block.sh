#!/usr/bin/env bash
#
# import_block.sh -- one-shot driver: fetch upstream at a pinned ref, run the
#                    per-block rename script, verify, and (optionally) commit.
#
#   ./tools/scripts/rename/import_block.sh ecc
#   ./tools/scripts/rename/import_block.sh hmac --ref v2.1.0 --commit
#   ./tools/scripts/rename/import_block.sh all  --upstream ~/src/caliptra-rtl
#
# If --upstream is not given, caliptra-rtl is cloned into a cache directory
# (.upstream-cache/, git-ignored) so the flow is reproducible on a clean
# machine.

set -euo pipefail

# shellcheck source=revinfo_lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/revinfo_lib.sh"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RENAME_DIR="$REPO_ROOT/tools/scripts/rename"
UPSTREAM_REPO="${TESSERA_UPSTREAM_REPO:-https://github.com/chipsalliance/caliptra-rtl.git}"
CACHE_DIR="$REPO_ROOT/.upstream-cache/caliptra-rtl"

BLOCKS=()
UPSTREAM=""
REF=""
PREFIX="${TESSERA_PREFIX:-tessera_}"
DO_COMMIT=0

usage() {
    sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
    cat <<EOF

options:
  --upstream <dir>   use an existing caliptra-rtl checkout instead of cloning
  --ref <ref>        upstream ref/tag/sha to import (default: default branch)
  --prefix <str>     identifier prefix (default: $PREFIX)
  --commit           git-commit the renamed fileset + revinfo into this repo
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --upstream) UPSTREAM="${2:?}"; shift 2 ;;
        --ref)      REF="${2:?}";      shift 2 ;;
        --prefix)   PREFIX="${2:?}";   shift 2 ;;
        --commit)   DO_COMMIT=1;       shift ;;
        --help|-h)  usage; exit 0 ;;
        -*)         usage >&2; echo "unknown option: $1" >&2; exit 2 ;;
        *)          BLOCKS+=("$1");    shift ;;
    esac
done

if [ "${#BLOCKS[@]}" -eq 0 ]; then usage >&2; exit 2; fi
if [ "${BLOCKS[0]}" = "all" ]; then
    BLOCKS=()
    for s in "$RENAME_DIR"/rename_*.sh; do
        b="$(basename "$s" .sh)"; b="${b#rename_}"
        [ "$b" = "common" ] && continue
        BLOCKS+=("$b")
    done
fi

for b in "${BLOCKS[@]}"; do
    [ -x "$RENAME_DIR/rename_$b.sh" ] || { echo "no rename script for block '$b'" >&2; exit 1; }
done

if [ -z "$UPSTREAM" ]; then
    if [ -d "$CACHE_DIR/.git" ]; then
        echo "== updating upstream cache =="
        git -C "$CACHE_DIR" fetch --tags --prune origin
    else
        echo "== cloning $UPSTREAM_REPO =="
        mkdir -p "$(dirname "$CACHE_DIR")"
        git clone "$UPSTREAM_REPO" "$CACHE_DIR"
    fi
    UPSTREAM="$CACHE_DIR"
fi

if [ -n "$REF" ]; then
    echo "== checking out upstream ref '$REF' =="
    git -C "$UPSTREAM" checkout --quiet --detach "$REF"
    git -C "$UPSTREAM" submodule update --init --recursive --quiet 2>/dev/null || true
fi

echo "== upstream: $(git -C "$UPSTREAM" rev-parse HEAD) =="

for b in "${BLOCKS[@]}"; do
    echo
    echo "======================================================================"
    echo " importing block: $b"
    echo "======================================================================"

    # Not every block lives on the same branch: hmac256 is only on `future`.
    # The branch each block tracks is recorded in its revinfo, so re-importing
    # "all" puts every block back on the branch it was taken from instead of
    # silently failing on the ones that are not on main. An explicit --ref
    # overrides this, because then the caller has pinned the tree deliberately.
    branch="main"
    if rev="$(ri_path "$REPO_ROOT" "$b" 2>/dev/null)" && [ -f "$rev" ]; then
        branch="$(sed -nE 's/^[[:space:]]*branch:[[:space:]]*"?([^",]+)"?.*/\1/p' "$rev" | head -1)"
        [ -n "$branch" ] || branch="main"
    fi
    if [ -z "$REF" ]; then
        echo "-- upstream branch: $branch"
        git -C "$UPSTREAM" checkout --quiet --detach "origin/$branch" 2>/dev/null \
            || git -C "$UPSTREAM" checkout --quiet --detach "$branch"
        git -C "$UPSTREAM" submodule update --init --recursive --quiet 2>/dev/null || true
    fi

    "$RENAME_DIR/rename_$b.sh" --upstream "$UPSTREAM" --dest "$REPO_ROOT" \
        --prefix "$PREFIX" --branch "$branch"
done

echo
"$RENAME_DIR/verify_import.sh" --dest "$REPO_ROOT"
"$RENAME_DIR/check_filelists.sh" --dest "$REPO_ROOT"

if [ "$DO_COMMIT" -eq 1 ]; then
    sha="$(git -C "$UPSTREAM" rev-parse --short=12 HEAD)"
    paths=()
    for b in "${BLOCKS[@]}"; do
        # Each block mirrors its own slice of the caliptra-rtl hierarchy, so the
        # paths to stage are read back out of the generated revinfo file rather
        # than assumed.
        rev="$(ri_path "$REPO_ROOT" "$b")"
        bdir="${rev%/*}"; bdir="${bdir#$REPO_ROOT/}"
        mapfile -t dirs < <(sed -nE '/^[[:space:]]*source_dirs:/,/^[[:space:]]*(collateral_dirs|filelist):/ s@^[[:space:]]*-[[:space:]]*(src/.*)$@\1@p' "$rev")
        mapfile -t cdirs < <(sed -nE '/^[[:space:]]*collateral_dirs:/,/^[[:space:]]*filelist:/ s@^[[:space:]]*-[[:space:]]*(src/.*)$@\1@p' "$rev")
        [ "${#cdirs[@]}" -eq 0 ] || dirs+=("${cdirs[@]}")
        fl="$(sed -nE 's/^[[:space:]]*filelist:[[:space:]]*(.*)$/\1/p' "$rev" | head -1)"
        paths+=("${dirs[@]}" "$fl" "$bdir/revinfo.yml" "$bdir/revinfo.map")
    done
    git -C "$REPO_ROOT" add -- "${paths[@]}"
    if git -C "$REPO_ROOT" diff --cached --quiet; then
        echo "nothing to commit"
    else
        git -C "$REPO_ROOT" commit -m "Import $(printf '%s ' "${BLOCKS[@]}")from caliptra-rtl@${sha}

Vendored with prefix '${PREFIX}' via tools/scripts/rename/.
Provenance recorded in src/<block>/revinfo.yml."
        echo "committed."
    fi
fi
