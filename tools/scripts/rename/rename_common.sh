#!/usr/bin/env bash
#
# rename_common.sh -- shared library for the Tessera crypto-block import/rename flow.
#
# This file is NOT executable on its own. Each crypto block has its own driver
# script (rename_ecc.sh, rename_hmac512.sh, ...) that declares the block-specific
# configuration and then calls `rc_run`.
#
# The blocks are similar but not identical: different directory hierarchies,
# different include-guard macro names, different environment-supplied
# configuration macros, and different cross-block dependencies. Keeping the
# common machinery here and the quirks in the per-block driver keeps each
# driver short and auditable.
#
# ---------------------------------------------------------------------------
# Contract for a per-block driver
# ---------------------------------------------------------------------------
# Required variables:
#   BLOCK                 short block name, e.g. "ecc"
#   UPSTREAM_SUBTREES     array of upstream dirs to import (repo-relative)
#
# Optional variables:
#   DEST_SUBTREES         array parallel to UPSTREAM_SUBTREES giving the Tessera
#                         path for each upstream subtree. Defaults to the
#                         identity mapping, so the Tessera tree mirrors the
#                         caliptra-rtl hierarchy exactly:
#                           caliptra-rtl  src/ecc/rtl/ecc_top.sv
#                           Tessera          src/ecc/rtl/tessera_ecc_top.sv
#                         Override only when Tessera deliberately shelves a block
#                         under a different name, e.g.
#                           DEST_SUBTREES=("src/hmac_512_384/rtl")
#   BLOCK_DIR             Tessera directory that owns the block's config/ dir.
#                         Defaults to the parent of DEST_SUBTREES[0].
#   UPSTREAM_BLOCK_DIR    upstream directory that BLOCK_DIR replaces. Setting
#                         both maps every upstream subtree -- delivery and
#                         collateral -- through the swap, so a block that is
#                         shelved under a different name states that once
#                         instead of mirroring each subtree by hand:
#                           UPSTREAM_BLOCK_DIR="src/ecc"
#                           BLOCK_DIR="src/ecc_ecdsa_ecdhe"
#                         An explicit DEST_SUBTREES/COLLATERAL_DEST_SUBTREES
#                         entry still wins, which is what a block whose sources
#                         do not sit under one upstream directory (ABR, whose
#                         RTL comes from a submodule) needs.
#   VF_FILELIST           upstream .vf filelist used to derive compile order
#                         (its basename is reused for the generated filelist)
#   VF_FILTER             egrep pattern selecting this block's lines in VF_FILELIST
#   EXCLUDE_GLOBS         array of basename globs never imported
#   EXTRA_RENAME_IDENTS   array of "kind:name" tokens that are declared outside
#                         this block but must still be renamed (cross-block deps)
#   ENV_MACRO_SPECS       array of "MACRO@upstream/path/to/header.svh" -- macros
#                         the *environment* applies to configure the block
#   ENV_HEADER_REPLACE    array of header basenames whose `include is redirected
#                         to the generated block-private config header
#   KEEP_IDENTS           array of identifiers that must NOT be prefixed
#   SUBMODULE_PATHS       array of paths, relative to the upstream checkout,
#                         whose RTL this block vendors but which are separate
#                         git repositories. Each is recorded as its own
#                         provenance entry: one caliptra-rtl commit is not
#                         enough to describe where the sources came from.
#   SUBMODULE_BRANCHES    optional, parallel to SUBMODULE_PATHS: the branch each
#                         submodule commit is reachable from. Recorded, and used
#                         to fetch when the commit is not in the local clone.
#   SUBMODULE_COMMITS     optional, parallel to SUBMODULE_PATHS: pin a submodule
#                         *ahead of the superproject gitlink*. Set it and the
#                         import checks that commit out before staging, instead
#                         of vendoring whatever `git submodule update` left
#                         behind. Empty entry = follow the gitlink, the normal
#                         case. See rc_position_submodules.
#   EXTRA_PATH_DIRS       array of directory names that appear as path
#                         components of foreign paths (doc URLs, upstream-repo
#                         references) and must keep their unprefixed spelling
#                         there even though the identifier itself is renamed
#                         (shared platform libraries owned by Tessera, not by the block)
#   COLLATERAL_SUBTREES   array of upstream dirs imported *recursively* as
#                         verification collateral (tb/, formal/, stimulus/,
#                         uvmf_*/ ...). Same identifier map, looser contract --
#                         see "Two tiers" below. Imported at the identity path.
#   ARTIFACT_GLOBS        basename globs treated as build/simulation *outputs*
#                         and never imported from any tier. Defaults below.
#
# ---------------------------------------------------------------------------
# Two tiers: delivery vs collateral
# ---------------------------------------------------------------------------
# UPSTREAM_SUBTREES is the *delivery*: the files Tessera ships in a netlist.
# Every name in it is prefixed, every file name is prefixed, the generated
# filelist covers it, and CI elaborates it. The contract is strict.
#
# COLLATERAL_SUBTREES is everything else in the block folder -- testbenches,
# formal properties, stimulus lists, UVMF generated output. It is imported so
# the block folder arrives whole and Tessera can reuse upstream verification, but
# the contract is looser on purpose:
#
#   * the same identifier map is applied, so collateral keeps referring to the
#     renamed RTL correctly;
#   * a collateral *file* is renamed only when its name is itself a renamed
#     identifier (ecc_top_tb.sv -> tessera_ecc_top_tb.sv), so Makefile,
#     compile.do and hmac_vectors_singleblk.txt keep their names;
#   * it is not elaborated in CI -- that needs UVM and a simulator licence.
#
# Build and simulation *outputs* (ARTIFACT_GLOBS: *.ucdb, *.exe, *.o, ...) are
# never imported from either tier. They are regenerated, not vendored.
#
# Optional hook functions:
#   block_pre_rename      run after staging, before the map is applied
#   block_post_rename     run after the map is applied, before files are renamed
# ---------------------------------------------------------------------------

set -euo pipefail

# Every sort in this file feeds a committed artifact (the rename map, the
# source manifest, the generated filelist), so collation order is part of the
# output. glibc's default en_US.UTF-8 collation ignores punctuation at the
# first comparison level, which puts "hmac.sv" after "hmac_param_pkg.sv",
# while C collation compares bytes and puts it first. Pin the locale so an
# import is reproducible across machines rather than only on the machine that
# happened to run it.
export LC_ALL=C

RC_SCRIPT_VERSION="2.1.1"

# ---------------------------------------------------------------------------
# Stem policy -- a second, repo-wide knob layered on top of the prefix.
#
# The prefix answers "could this collide in an Tessera netlist". It does not
# answer "can a reader tell these two blocks apart". caliptra-rtl calls its
# HMAC-SHA512 engine plain `hmac` and its HMAC-SHA256 engine `hmac256`, so a
# faithful import gives Tessera tessera_hmac_core next to tessera_hmac256_core and the
# shorter name is the *less* obvious one. Tessera shelves the SHA-512 engine as
# hmac512 instead, both as a directory and as an identifier stem.
#
# Why this lives here and not in rename_hmac512.sh: identifiers cross block
# boundaries. ECC instantiates hmac_drbg and imports hmac_param_pkg, so ECC
# has to spell the renamed package exactly the way the HMAC import minted it.
# Two drivers holding two copies of the same naming decision is how they drift.
# One declaration, applied by every driver, cannot.
#
# Entries are "<from>=<to>", matched against a whole identifier or the leading
# component of one ("hmac" and "hmac_core", not "hmac256" and not
# "ecc_hmac_drbg_interface"). RC_STEM_KEEP exempts names that merely begin with
# the same token: hmac_drbg is a DRBG shared with ECC, not a SHA-512 HMAC, so it
# keeps its upstream name -- and, being its own import, its own src/hmac_drbg/
# directory and its own revinfo.
#
# A driver may override both arrays before sourcing this file.
# ---------------------------------------------------------------------------
RC_DEFAULT_STEM_RENAMES=( "hmac=hmac512" )
RC_DEFAULT_STEM_KEEP=( "hmac_drbg" )

rc_log()  { printf '[%s] %s\n' "${BLOCK:-rename}" "$*"; }
rc_warn() { printf '[%s] WARNING: %s\n' "${BLOCK:-rename}" "$*" >&2; }
rc_die()  { printf '[%s] ERROR: %s\n' "${BLOCK:-rename}" "$*" >&2; exit 1; }

rc_usage() {
    cat <<EOF
usage: $(basename "$0") --upstream <caliptra-rtl-checkout> [options]

  --upstream  <dir>   path to a caliptra-rtl git checkout (required)
  --dest      <dir>   Tessera repo root (default: repo root of this script)
  --prefix    <str>   identifier prefix, lowercase, trailing underscore
                      (default: \$TESSERA_PREFIX or "tessera_")
  --branch    <name>  upstream branch this block tracks, recorded in revinfo
                      so you know what to diff against later (default: main)
  --keep-work         do not delete the temporary staging directory
  --help              show this message
EOF
}

# ---------------------------------------------------------------------------
# rc_init -- argument parsing and environment discovery
# ---------------------------------------------------------------------------
rc_default_array() {
    local name
    for name in "$@"; do
        declare -p "$name" >/dev/null 2>&1 || eval "$name=()"
    done
}

# Guard the destination paths. rc_install removes these directories before
# repopulating them, so anything outside src/ or containing '..' is refused.
rc_check_relpath() {
    local p="$1"
    case "$p" in
        src/*) : ;;
        *) rc_die "destination path '$p' must live under src/" ;;
    esac
    case "$p" in
        *..*|*//*|/*) rc_die "destination path '$p' is not a clean relative path" ;;
    esac
}

# Map one upstream subtree into the block's Tessera directory by swapping the
# UPSTREAM_BLOCK_DIR prefix for BLOCK_DIR. A subtree that does not sit under
# UPSTREAM_BLOCK_DIR is a driver bug: it would silently land at its upstream
# path while its siblings moved, which is how half-renamed trees happen.
rc_blockdir_remap() {
    local up="$1"
    case "$up" in
        "$UPSTREAM_BLOCK_DIR") printf '%s' "$BLOCK_DIR" ;;
        "$UPSTREAM_BLOCK_DIR"/*) printf '%s/%s' "$BLOCK_DIR" "${up#"$UPSTREAM_BLOCK_DIR"/}" ;;
        *) rc_die "subtree '$up' is not under UPSTREAM_BLOCK_DIR '$UPSTREAM_BLOCK_DIR'; give it an explicit DEST_SUBTREES entry" ;;
    esac
}

# Build / simulation outputs. Checked into caliptra-rtl in a few places, but
# they are derived files: vendoring them would commit stale results and bloat
# the Tessera history. Regenerate instead.
RC_DEFAULT_ARTIFACT_GLOBS=(
    '*.ucdb' '*.exe' '*.o' '*.a' '*.so' '*.pyc' '*.wlf' '*.vstf' '*.vcd' '*.fsdb'
)

# Rename scope: synthesized design material only.
#
# The prefix exists to keep the Tessera *design* namespace from colliding with an
# upstream Caliptra instance in the same elaboration. That is a property of the
# synthesized netlist, so only identifiers *declared* in synthesizable RTL are
# renamed. SYNTH_SUBTREES names those directories; it defaults to every
# delivery subtree called "rtl".
#
# The rename map is still applied to *every* vendored file, which is the part
# that is easy to misread as a contradiction. Declaring and referencing are
# different things: the benches under tb/, formal/ and the UVMF tree keep their
# own upstream names, but they instantiate ecc_top, and ecc_top is now
# tessera_ecc_top -- so their references have to follow or the vendored bench no
# longer binds to the vendored RTL. One rule covers both tiers:
#
#     rename what is declared in synthesizable RTL;
#     rewrite references to it everywhere; rename nothing else.
#
# Code-generator inputs. A block may vendor files that are *fed to* a generator
# rather than compiled -- the UVMF .yaml descriptions are the case here. They
# must come through byte-identical to upstream or regeneration silently
# diverges from what is committed, and the round-trip cannot catch that on its
# own: it strips the prefix before comparing, so a yaml that had wrongly been
# prefixed would strip back to the upstream text and pass. Listing them here
# makes the invariant checkable. See rc_check_generator_inputs.
rc_init() {
    rc_default_array EXCLUDE_GLOBS EXTRA_RENAME_IDENTS ENV_MACRO_SPECS \
                     ENV_HEADER_REPLACE KEEP_IDENTS DEST_SUBTREES \
                     COLLATERAL_SUBTREES ARTIFACT_GLOBS GENERATOR_INPUTS \
                     SYNTH_SUBTREES EXTRA_PATH_DIRS SUBMODULE_PATHS \
                     SUBMODULE_BRANCHES SUBMODULE_COMMITS \
                     COLLATERAL_DEST_SUBTREES STEM_RENAMES STEM_KEEP
    [ "${#ARTIFACT_GLOBS[@]}" -gt 0 ] || ARTIFACT_GLOBS=("${RC_DEFAULT_ARTIFACT_GLOBS[@]}")
    [ "${#STEM_RENAMES[@]}" -gt 0 ]   || STEM_RENAMES=("${RC_DEFAULT_STEM_RENAMES[@]}")
    [ "${#STEM_KEEP[@]}" -gt 0 ]      || STEM_KEEP=("${RC_DEFAULT_STEM_KEEP[@]}")
    WITH_COLLATERAL=1

    UPSTREAM=""
    DEST=""
    PREFIX="${TESSERA_PREFIX:-tessera_}"
    KEEP_WORK=0

    while [ $# -gt 0 ]; do
        case "$1" in
            --upstream) UPSTREAM="${2:?--upstream needs a value}"; shift 2 ;;
            --dest)     DEST="${2:?--dest needs a value}";         shift 2 ;;
            --prefix)   PREFIX="${2:?--prefix needs a value}";     shift 2 ;;
            --branch)   UPSTREAM_BRANCH="${2:?--branch needs a value}"; shift 2 ;;
            --keep-work) KEEP_WORK=1; shift ;;
            --no-collateral) WITH_COLLATERAL=0; shift ;;
            --help|-h)  rc_usage; exit 0 ;;
            *) rc_usage >&2; rc_die "unknown argument: $1" ;;
        esac
    done

    [ -n "$UPSTREAM" ] || { rc_usage >&2; rc_die "--upstream is required"; }
    # not -d "$UPSTREAM/.git": in a linked worktree .git is a file, and a
    # worktree is how you check out a second branch of the same clone -- which
    # is exactly what importing a block that only exists on `future` needs.
    git -C "$UPSTREAM" rev-parse --git-dir >/dev/null 2>&1 \
        || rc_die "'$UPSTREAM' is not a git checkout"

    # SUBMODULE_BRANCHES / SUBMODULE_COMMITS are indexed by SUBMODULE_PATHS, so
    # a short array is not "the rest defaulted", it is a driver that grew an
    # entry on one list and not the other. Reject it rather than silently
    # vendoring a submodule nobody declared a ref for.
    local n
    for n in SUBMODULE_BRANCHES SUBMODULE_COMMITS; do
        eval "local len=\${#$n[@]}"
        [ "$len" -eq 0 ] || [ "$len" -eq "${#SUBMODULE_PATHS[@]}" ] \
            || rc_die "$n has $len entr(y|ies) but SUBMODULE_PATHS has ${#SUBMODULE_PATHS[@]}"
    done

    RC_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -z "$DEST" ]; then
        DEST="$(cd "$RC_LIB_DIR/../../.." && pwd)"
    fi
    [ -d "$DEST" ] || rc_die "destination '$DEST' does not exist"

    UPSTREAM="$(cd "$UPSTREAM" && pwd)"
    DEST="$(cd "$DEST" && pwd)"

    case "$PREFIX" in
        *_) : ;;
        *)  rc_die "prefix '$PREFIX' must end with an underscore" ;;
    esac
    MACRO_PREFIX="$(printf '%s' "$PREFIX" | tr '[:lower:]' '[:upper:]')"

    # ------------------------------------------------------------------
    # Destination layout.
    #
    # Tessera mirrors the caliptra-rtl hierarchy: an upstream src/<block>/rtl
    # lands at src/<block>/rtl in Tessera, so the correspondence between the two
    # trees is 1:1 and a re-import shows up as an ordinary RTL diff. A driver
    # may override individual paths via DEST_SUBTREES.
    # ------------------------------------------------------------------
    local i dst
    # A block whose Tessera directory differs from its upstream one declares
    # that once, as UPSTREAM_BLOCK_DIR + BLOCK_DIR, and every subtree is mapped
    # through it. The alternative is a DEST_SUBTREES entry per upstream entry,
    # parallel arrays that have to be kept in step by hand -- the same drift
    # hazard the drivers avoid for identifier policy. An explicit DEST_SUBTREES
    # entry still wins, for a block like ABR whose sources come from a
    # submodule and so have no upstream path that a single swap can express.
    if [ -n "${UPSTREAM_BLOCK_DIR:-}" ]; then
        [ -n "${BLOCK_DIR:-}" ] || \
            rc_die "UPSTREAM_BLOCK_DIR set without BLOCK_DIR"
        for i in "${!UPSTREAM_SUBTREES[@]}"; do
            [ -n "${DEST_SUBTREES[$i]:-}" ] && continue
            DEST_SUBTREES[$i]="$(rc_blockdir_remap "${UPSTREAM_SUBTREES[$i]}")"
        done
        for i in "${!COLLATERAL_SUBTREES[@]}"; do
            [ -n "${COLLATERAL_DEST_SUBTREES[$i]:-}" ] && continue
            COLLATERAL_DEST_SUBTREES[$i]="$(rc_blockdir_remap "${COLLATERAL_SUBTREES[$i]}")"
        done
    fi
    for i in "${!UPSTREAM_SUBTREES[@]}"; do
        dst="${DEST_SUBTREES[$i]:-${UPSTREAM_SUBTREES[$i]}}"
        rc_check_relpath "$dst"
        DEST_SUBTREES[$i]="$dst"
    done
    BLOCK_DIR="${BLOCK_DIR:-$(dirname "${DEST_SUBTREES[0]}")}"
    rc_check_relpath "$BLOCK_DIR"

    GENERATOR_INPUTS_DEST=()
    local gi
    for gi in "${GENERATOR_INPUTS[@]}"; do
        GENERATOR_INPUTS_DEST+=("$(rc_gi_dest "$gi")")
    done
    CONFIG_DIR="$BLOCK_DIR/config"

    # Synthesized design material. Default: every delivery subtree called
    # "rtl". A block whose synthesizable sources live elsewhere overrides this.
    if [ "${#SYNTH_SUBTREES[@]}" -eq 0 ]; then
        for dst in "${DEST_SUBTREES[@]}"; do
            [ "$(basename "$dst")" = "rtl" ] && SYNTH_SUBTREES+=("$dst")
        done
    fi
    [ "${#SYNTH_SUBTREES[@]}" -gt 0 ] || \
        rc_die "no synthesizable subtree identified; set SYNTH_SUBTREES in the driver"
    for dst in "${SYNTH_SUBTREES[@]}"; do
        rc_check_relpath "$dst"
        case " ${DEST_SUBTREES[*]} " in
            *" $dst "*) ;;
            *) rc_die "SYNTH_SUBTREES entry '$dst' is not a delivery subtree" ;;
        esac
    done

    # Provenance lives *inside* the block it describes, so copying src/ecc/
    # anywhere carries the record of where it came from with it.
    OUT_REVINFO="$DEST/$BLOCK_DIR"
    WORK="$(mktemp -d "${TMPDIR:-/tmp}/tessera-import-$BLOCK-XXXXXX")"
    STAGE="$WORK/stage"
    MAP="$WORK/map.tsv"
    mkdir -p "$STAGE" "$OUT_REVINFO"

    if [ "$KEEP_WORK" -eq 0 ]; then
        trap 'rm -rf "$WORK"' EXIT
    else
        rc_log "staging dir kept at $WORK"
    fi

    UPSTREAM_URL="$(git -C "$UPSTREAM" config --get remote.origin.url || echo 'unknown')"
    UPSTREAM_SHA="$(git -C "$UPSTREAM" rev-parse HEAD)"
    UPSTREAM_DESC="$(git -C "$UPSTREAM" log -1 --format='%s' HEAD)"
    UPSTREAM_DATE="$(git -C "$UPSTREAM" log -1 --format='%cI' HEAD)"
    # The branch is declared, not observed. Its only job is to tell a future
    # maintainer what to diff the pinned commit against ("what landed upstream
    # since we imported"), which is a property of the tracking policy, not of
    # whatever the local clone happens to have checked out. Observing it made
    # the import unreproducible: a CI job checks the pinned sha out detached,
    # so `rev-parse --abbrev-ref HEAD` returned "HEAD".
    UPSTREAM_BRANCH="${UPSTREAM_BRANCH:-main}"
    local on_branch
    on_branch="$(git -C "$UPSTREAM" rev-parse --abbrev-ref HEAD)"
    if [ "$on_branch" != "HEAD" ] && [ "$on_branch" != "$UPSTREAM_BRANCH" ]; then
        rc_warn "upstream clone is on '$on_branch' but recording branch '$UPSTREAM_BRANCH'; pass --branch to change"
    fi
    if [ -n "$(git -C "$UPSTREAM" status --porcelain -- $(printf '%s ' "${UPSTREAM_SUBTREES[@]}"))" ]; then
        UPSTREAM_DIRTY="true"
        rc_warn "upstream working tree is dirty for the imported subtrees"
    else
        UPSTREAM_DIRTY="false"
    fi

    rc_log "upstream : $UPSTREAM @ $UPSTREAM_SHA"
    rc_log "dest     : $DEST"
    rc_log "prefix   : $PREFIX (macros: $MACRO_PREFIX)"
    [ "${#STEM_RENAMES[@]}" -gt 0 ] && \
        rc_log "stems    : $(printf '%s ' "${STEM_RENAMES[@]}")(keep: $(printf '%s ' "${STEM_KEEP[@]}"))"
}

# ---------------------------------------------------------------------------
# rc_position_submodules -- enact the submodule pins the driver declared.
#
# A submodule's commit normally comes from the superproject gitlink, so the
# caliptra-rtl commit alone determines the whole import and nobody has to think
# about it. Sometimes that is not what we want to ship: ABR's sources move in
# adams-bridge much faster than caliptra-rtl bumps its pointer at them, so
# Tessera can need a commit the gitlink does not name yet.
#
# Expressing that only in the checkout would make the import unreproducible --
# `git submodule update` would silently undo it and the next re-import would
# vendor different RTL while reporting success. So the pin is declared here, in
# the driver, as a branch plus a commit (what a gitlink is, spelled out), and
# the engine moves the checkout to match before it stages anything. The branch
# is what makes the commit fetchable; the commit is what makes it reproducible.
#
# An empty SUBMODULE_COMMITS entry means "follow the gitlink", which is the
# normal case and leaves the checkout untouched.
# ---------------------------------------------------------------------------
rc_position_submodules() {
    local i sp want branch have
    for i in "${!SUBMODULE_PATHS[@]}"; do
        want="${SUBMODULE_COMMITS[$i]:-}"
        [ -n "$want" ] || continue
        sp="${SUBMODULE_PATHS[$i]}"
        branch="${SUBMODULE_BRANCHES[$i]:-}"
        [ -n "$branch" ] || rc_die "SUBMODULE_COMMITS[$i] set without SUBMODULE_BRANCHES[$i]"
        git -C "$UPSTREAM/$sp" rev-parse --git-dir >/dev/null 2>&1 \
            || rc_die "submodule '$sp' is not checked out (git submodule update --init?)"

        have="$(git -C "$UPSTREAM/$sp" rev-parse HEAD)"
        if [ "$have" != "$want" ]; then
            git -C "$UPSTREAM/$sp" cat-file -e "$want^{commit}" 2>/dev/null \
                || git -C "$UPSTREAM/$sp" fetch --quiet origin \
                       "+refs/heads/$branch:refs/remotes/origin/$branch" \
                || rc_die "cannot fetch $branch from submodule '$sp'"
            git -C "$UPSTREAM/$sp" checkout --quiet --detach "$want" \
                || rc_die "submodule '$sp' has no commit $want on $branch"
            # the pinned commit may carry nested submodules of its own, and they
            # are pinned by it, not by the gitlink we just left.
            git -C "$UPSTREAM/$sp" submodule update --init --recursive --quiet
            rc_log "submodule $sp -> ${want:0:12} ($branch), ahead of the gitlink"
        fi
        have="$(git -C "$UPSTREAM/$sp" rev-parse HEAD)"
        [ "$have" = "$want" ] || rc_die "submodule '$sp' is at $have, expected $want"

        # The commit being present locally does not prove the recorded branch is
        # the one it came from -- a stale object in someone's clone would let a
        # wrong SUBMODULE_BRANCHES entry pass here and fail in a fresh one. Check
        # the pair when we have the ref to check it against, which is whenever a
        # fetch has happened; don't force one just for the assertion, since the
        # import otherwise works offline.
        if git -C "$UPSTREAM/$sp" rev-parse --verify --quiet "refs/remotes/origin/$branch" >/dev/null; then
            git -C "$UPSTREAM/$sp" merge-base --is-ancestor "$want" "refs/remotes/origin/$branch" \
                || rc_die "submodule '$sp': $want is not reachable from origin/$branch"
        fi
    done
}

# ---------------------------------------------------------------------------
# rc_stage -- copy the upstream subtrees into a staging tree that already has
#             the final Tessera layout (src/<block>/rtl/...), so nothing downstream
#             has to reconstruct where a file belongs.
#
# STAGED_FILES holds repo-relative paths, e.g. "src/ecc/rtl/ecc_top.sv".
# ---------------------------------------------------------------------------
rc_stage() {
    local i subtree dst src base rel skip glob
    STAGED_FILES=()
    SRC_MANIFEST="$WORK/src_manifest.txt"
    FILE_RENAMES="$WORK/file_renames.tsv"
    : > "$FILE_RENAMES"
    : > "$SRC_MANIFEST"

    for i in "${!UPSTREAM_SUBTREES[@]}"; do
        subtree="${UPSTREAM_SUBTREES[$i]}"
        dst="${DEST_SUBTREES[$i]}"
        [ -d "$UPSTREAM/$subtree" ] || rc_die "upstream subtree '$subtree' not found"
        mkdir -p "$STAGE/$dst"
        while IFS= read -r src; do
            base="$(basename "$src")"
            skip=0
            for glob in "${EXCLUDE_GLOBS[@]}"; do
                [ -n "$glob" ] || continue
                # shellcheck disable=SC2053
                if [[ "$base" == $glob ]]; then skip=1; break; fi
            done
            if [ "$skip" -eq 1 ]; then
                rc_log "  excluded  $subtree/$base"
                continue
            fi
            # Module and file names must stay unique across the whole block
            # even though they now live in different directories.
            rc_assert_unique_basename "$base"
            rel="$dst/$base"
            cp "$src" "$STAGE/$rel"
            STAGED_FILES+=("$rel")
            printf '%s  %s/%s\n' "$(sha256sum "$src" | cut -d' ' -f1)" "$subtree" "$base" >> "$SRC_MANIFEST"
        done < <(find "$UPSTREAM/$subtree" -maxdepth 1 -type f | sort)
        if [ "$dst" != "$subtree" ]; then
            rc_log "  subtree   $subtree -> $dst"
        else
            rc_log "  subtree   $subtree"
        fi
    done

    [ "${#STAGED_FILES[@]}" -gt 0 ] || rc_die "nothing staged"
    rc_log "staged ${#STAGED_FILES[@]} file(s) into ${#DEST_SUBTREES[@]} director(ies)"
}

# ---------------------------------------------------------------------------
# rc_stage_collateral -- recursively stage the rest of the block folder.
#
# Unlike the delivery subtrees this walks the whole tree and preserves every
# intermediate directory, so src/ecc/uvmf_ecc/uvmf_template_output/... lands at
# the same path in Tessera. Basenames are allowed to repeat here (there are four
# different Makefiles under src/ecc/uvmf_ecc alone) precisely because the full
# path is preserved.
# ---------------------------------------------------------------------------
rc_stage_collateral() {
    COLLATERAL_FILES=()
    # Declared here, not only assigned in rc_rename_collateral_files, so that a
    # block with no collateral still has an empty array for the fixup passes.
    COLLATERAL_INSTALLED=()
    COLLATERAL_BINARIES=()
    COLLATERAL_DIRS=()
    [ "${#COLLATERAL_SUBTREES[@]}" -gt 0 ] || return 0
    if [ "$WITH_COLLATERAL" -eq 0 ]; then
        rc_log "collateral skipped (--no-collateral)"
        return 0
    fi

    local subtree dst src rel base skip glob n_txt=0 n_bin=0 n_art=0 i
    for i in "${!COLLATERAL_SUBTREES[@]}"; do
        subtree="${COLLATERAL_SUBTREES[$i]}"
        [ -n "$subtree" ] || continue
        # Collateral normally lands at the same path it came from -- that is the
        # whole point of mirroring caliptra-rtl's hierarchy. ABR is the exception:
        # its sources come from a submodule, so the upstream path is not a legal
        # Tessera path and the driver has to say where it goes.
        dst="${COLLATERAL_DEST_SUBTREES[$i]:-$subtree}"
        [ -d "$UPSTREAM/$subtree" ] || rc_die "collateral subtree '$subtree' not found"
        rc_check_relpath "$dst"
        COLLATERAL_DIRS+=("$dst")
        while IFS= read -r src; do
            rel="$dst/${src#$UPSTREAM/$subtree/}"
            base="$(basename "$src")"
            skip=0
            for glob in "${ARTIFACT_GLOBS[@]}" "${EXCLUDE_GLOBS[@]}"; do
                [ -n "$glob" ] || continue
                # shellcheck disable=SC2053
                if [[ "$base" == $glob ]]; then skip=1; break; fi
            done
            if [ "$skip" -eq 1 ]; then n_art=$((n_art+1)); continue; fi

            mkdir -p "$STAGE/$(dirname "$rel")"
            cp "$src" "$STAGE/$rel"
            # The manifest is a record of what was *taken*, so it is keyed by
            # the upstream path even when the file is installed elsewhere.
            # roundtrip_check.sh maps it back through collateral_subtrees.
            printf '%s  %s\n' "$(sha256sum "$src" | cut -d' ' -f1)" \
                   "$subtree/${src#$UPSTREAM/$subtree/}" >> "$SRC_MANIFEST"
            # Text files take the identifier map; anything else is carried
            # through byte-for-byte (PDFs, reference diagrams, ...).
            if grep -Iq . "$src" 2>/dev/null; then
                COLLATERAL_FILES+=("$rel"); n_txt=$((n_txt+1))
            else
                COLLATERAL_BINARIES+=("$rel"); n_bin=$((n_bin+1))
            fi
        done < <(find "$UPSTREAM/$subtree" -type f | sort)
        if [ "$dst" != "$subtree" ]; then
            rc_log "  collateral $subtree -> $dst"
        else
            rc_log "  collateral $subtree"
        fi
    done
    rc_log "staged $n_txt collateral text file(s), $n_bin binary, $n_art artifact(s) skipped"
}

rc_assert_unique_basename() {
    local base="$1" f
    for f in "${STAGED_FILES[@]}"; do
        [ "$(basename "$f")" = "$base" ] && rc_die "basename collision while staging: $base"
    done
    return 0
}

# ---------------------------------------------------------------------------
# rc_build_map -- collect every identifier this block owns and build the
#                 original -> renamed mapping table.
# ---------------------------------------------------------------------------
# rc_stem -- apply the stem policy to one lowercase name.
#
# Operates on identifiers and on file basenames alike: "hmac" -> "hmac512",
# "hmac_core" -> "hmac512_core", "hmac.sv" -> "hmac512.sv". A name that merely
# starts with the same characters is untouched ("hmac256"), and a name on the
# keep list is untouched together with everything derived from it
# ("hmac_drbg", "hmac_drbg.sv", "hmac_drbg_pkg").
# ---------------------------------------------------------------------------
rc_stem() {
    local n="$1" r from to
    for r in "${STEM_KEEP[@]}"; do
        [ -n "$r" ] || continue
        case "$n" in "$r"|"$r"_*|"$r".*) printf '%s' "$n"; return 0 ;; esac
    done
    for r in "${STEM_RENAMES[@]}"; do
        [ -n "$r" ] || continue
        from="${r%%=*}"; to="${r#*=}"
        [ -n "$from" ] && [ "$from" != "$r" ] || rc_die "malformed STEM_RENAMES entry '$r' (want <from>=<to>)"
        case "$n" in
            "$from"|"$from"_*|"$from".*) printf '%s%s' "$to" "${n#"$from"}"; return 0 ;;
        esac
    done
    printf '%s' "$n"
}

# Same policy over an upper-case macro name: HMAC_PARAM_PKG -> HMAC512_PARAM_PKG.
rc_stem_macro() {
    local n="$1" low out
    low="$(printf '%s' "$n" | tr '[:upper:]' '[:lower:]')"
    out="$(rc_stem "$low")"
    [ "$out" = "$low" ] && { printf '%s' "$n"; return 0; }
    printf '%s' "$out" | tr '[:lower:]' '[:upper:]'
}

# The two public entry points. Every site that mints a new name goes through
# one of these, so the prefix and the stem can never disagree about a name.
rc_renamed_ident() {
    local kind="$1" name="$2"
    if [ "$kind" = "macro" ]; then
        printf '%s%s' "$MACRO_PREFIX" "$(rc_stem_macro "$name")"
    else
        printf '%s%s' "$PREFIX" "$(rc_stem "$name")"
    fi
}

rc_renamed_basename() { printf '%s%s' "$PREFIX" "$(rc_stem "$1")"; }

# ---------------------------------------------------------------------------
# rc_is_synth -- is this staged path inside a synthesizable subtree?
rc_is_synth() {
    local p="$1" d
    for d in "${SYNTH_SUBTREES[@]}"; do
        case "$p" in "$d"/*) return 0 ;; esac
    done
    return 1
}

rc_build_map() {
    local f kind name tok keep hit
    : > "$MAP.raw"

    pushd "$STAGE" >/dev/null
    for f in "${STAGED_FILES[@]}" "${COLLATERAL_FILES[@]}"; do
        case "$f" in *.sv|*.svh|*.v|*.vh) ;; *) continue ;; esac
        # Only synthesizable RTL contributes *new* names. Benches, coverage
        # binds and UVMF components keep their upstream identifiers; they are
        # not in the netlist, so they cannot collide there, and leaving them
        # alone is what keeps the UVMF generator inputs usable.
        rc_is_synth "$f" || continue
        # Declarations owned by the block.
        grep -hoE '^[[:space:]]*(module|package|interface)[[:space:]]+[A-Za-z_][A-Za-z0-9_$]*' "$f" 2>/dev/null \
            | sed -E 's/^[[:space:]]*//; s/[[:space:]]+/\t/' >> "$MAP.raw" || true
        # Include-guard / helper macros defined inside the block.
        grep -hoE '^[[:space:]]*`define[[:space:]]+[A-Za-z_][A-Za-z0-9_$]*' "$f" 2>/dev/null \
            | sed -E 's/^[[:space:]]*`define[[:space:]]+/macro\t/' >> "$MAP.raw" || true
    done
    popd >/dev/null

    # Cross-block dependencies declared by the driver (e.g. ECC instantiating
    # hmac_drbg, which is owned by the hmac_drbg import).
    for tok in "${EXTRA_RENAME_IDENTS[@]}"; do
        [ -n "$tok" ] || continue
        printf '%s\t%s\n' "${tok%%:*}" "${tok#*:}" >> "$MAP.raw"
    done

    # Environment-supplied configuration macros.
    for tok in "${ENV_MACRO_SPECS[@]}"; do
        [ -n "$tok" ] || continue
        printf 'macro\t%s\n' "${tok%%@*}" >> "$MAP.raw"
    done

    : > "$MAP"
    {
        printf '# Tessera identifier rename map\n'
        printf '# block=%s prefix=%s generator=rename_common.sh/%s\n' "$BLOCK" "$PREFIX" "$RC_SCRIPT_VERSION"
        printf '# kind\toriginal\trenamed\n'
    } >> "$MAP"

    while IFS=$'\t' read -r kind name; do
        [ -n "${name:-}" ] || continue
        keep=0
        for tok in "${KEEP_IDENTS[@]}"; do
            [ -n "$tok" ] || continue
            [ "$tok" = "$name" ] && { keep=1; break; }
        done
        if [ "$keep" -eq 1 ]; then
            rc_log "  keep-list $kind $name (shared platform identifier)"
            continue
        fi
        case "$name" in
            "$PREFIX"*|"$MACRO_PREFIX"*)
                rc_warn "'$name' already carries the prefix; skipped"
                continue ;;
        esac
        printf '%s\t%s\t%s\n' "$kind" "$name" "$(rc_renamed_ident "$kind" "$name")" >> "$MAP"
    done < <(sort -u "$MAP.raw")

    # File renames are recorded for traceability; apply_map.pl ignores them.
    # Recorded as full repo-relative paths on both sides, so the row stays
    # readable for a block whose directory moved as well as its file names.
    for f in "${STAGED_FILES[@]}"; do
        rc_is_synth "$f" || continue
        printf 'file\t%s\t%s/%s\n' "$f" "$(dirname "$f")" \
               "$(rc_renamed_basename "$(basename "$f")")" >> "$MAP"
    done

    hit="$(grep -cvE '^\s*(#|$)' "$MAP" || true)"
    [ "$hit" -gt 0 ] || rc_die "rename map is empty"
    rc_log "map contains $hit entry(ies)"
}

# ---------------------------------------------------------------------------
# rc_hold_out_generator_inputs / rc_restore_generator_inputs
#
# Move the generator inputs aside for the duration of a content pass and put
# them back afterwards. Filtering them out of the file lists instead would mean
# touching three call sites and getting the collateral path mapping right in
# each; moving the files is one mechanism that covers every pass, present and
# future, and fails loudly if a path is wrong.
# ---------------------------------------------------------------------------
# GENERATOR_INPUTS are declared as *upstream* paths, because that is the only
# name the file has that is stable across a re-import -- and the only one
# roundtrip_check.sh can hand to `git show`. For every block but a relocating
# one the Tessera path is the same string; ABR's is not, and nor is hmac512's.
# Translate once, here, through the same collateral dirmap rc_stage_collateral
# uses, instead of leaving three call sites to each get it right.
rc_gi_dest() {
    local gi="$1" i up ar best="" bestlen=0
    for i in "${!COLLATERAL_SUBTREES[@]}"; do
        up="${COLLATERAL_SUBTREES[$i]}"
        [ -n "$up" ] || continue
        case "$gi" in "$up"/*)
            [ "${#up}" -gt "$bestlen" ] && { bestlen="${#up}"; best="$i"; } ;;
        esac
    done
    if [ -n "$best" ]; then
        up="${COLLATERAL_SUBTREES[$best]}"
        ar="${COLLATERAL_DEST_SUBTREES[$best]:-$up}"
        printf '%s%s' "$ar" "${gi#"$up"}"
    else
        printf '%s' "$gi"
    fi
}

rc_is_generator_input() {
    local f="$1" gi
    [ "${#GENERATOR_INPUTS_DEST[@]}" -gt 0 ] || return 1
    for gi in "${GENERATOR_INPUTS_DEST[@]}"; do
        [ "$gi" = "$f" ] && return 0
    done
    return 1
}

RC_GI_HELD=()
rc_hold_out_generator_inputs() {
    RC_GI_HELD=()
    [ "${#GENERATOR_INPUTS_DEST[@]}" -gt 0 ] || return 0
    local gi
    for gi in "${GENERATOR_INPUTS_DEST[@]}"; do
        [ -n "$gi" ] || continue
        [ -f "$STAGE/$gi" ] || continue
        mv "$STAGE/$gi" "$STAGE/$gi.rc-held"
        RC_GI_HELD+=("$gi")
    done
    [ "${#RC_GI_HELD[@]}" -gt 0 ] && \
        rc_log "  holding ${#RC_GI_HELD[@]} generator input(s) out of the content pass"
    return 0
}

rc_restore_generator_inputs() {
    [ "${#RC_GI_HELD[@]}" -gt 0 ] || return 0
    local gi
    for gi in "${RC_GI_HELD[@]}"; do
        mv "$STAGE/$gi.rc-held" "$STAGE/$gi"
    done
    RC_GI_HELD=()
}

# ---------------------------------------------------------------------------
# rc_apply -- one perl pass per file using the full map
# ---------------------------------------------------------------------------
rc_apply() {
    local f
    rc_log "applying rename map"
    # Generator inputs are held out of every content pass. They are read by a
    # code generator, not compiled, and the names in them are UVM class names
    # that merely happen to spell the same string as a design name: HMAC256's
    # bench yaml names an environment "hmac256", which is also the module.
    # Rewriting it would make the committed bench disagree with what the
    # generator would next produce from it.
    local pass=()
    for f in "${STAGED_FILES[@]}" "${COLLATERAL_FILES[@]}"; do
        rc_is_generator_input "$f" && continue
        pass+=("$f")
    done
    pushd "$STAGE" >/dev/null
    perl "$RC_LIB_DIR/lib/apply_map.pl" "$MAP" "${pass[@]}"
    popd >/dev/null

    # Idempotency guard: a double prefix means the map was applied twice or an
    # entry overlapped another entry.
    if grep -rqE "(${PREFIX}){2}|(${MACRO_PREFIX}){2}" "$STAGE"; then
        grep -rnE "(${PREFIX}){2}|(${MACRO_PREFIX}){2}" "$STAGE" | head >&2
        rc_die "double-prefixed identifiers detected"
    fi
}

# ---------------------------------------------------------------------------
# rc_env_macros -- materialise a block-private configuration header holding the
#                  (now prefixed) macros the environment used to supply, and
#                  redirect the corresponding `include directives to it.
# ---------------------------------------------------------------------------
rc_env_macros() {
    ENV_HEADER=""
    [ "${#ENV_MACRO_SPECS[@]}" -gt 0 ] || return 0

    local spec macro src line guard hdr hdr_dir
    # The generated header belongs next to the RTL that includes it.
    hdr_dir="$(dirname "${STAGED_FILES[0]}")"
    hdr="$hdr_dir/${PREFIX}${BLOCK}_config.svh"
    ENV_HEADER="$hdr"
    guard="$(printf '%s%s_CONFIG_SVH' "$MACRO_PREFIX" "$(printf '%s' "$BLOCK" | tr '[:lower:]' '[:upper:]')")"

    {
        printf '// SPDX-License-Identifier: Apache-2.0\n'
        printf '//\n'
        printf '// GENERATED by tools/scripts/rename/rename_%s.sh -- do not edit by hand.\n' "$BLOCK"
        printf '//\n'
        printf '// Configuration macros that the caliptra-rtl *environment* used to apply to\n'
        printf '// the %s block. They are captured here, under the Tessera prefix, so the imported\n' "$BLOCK"
        printf '// block no longer depends on caliptra-rtl global headers.\n'
        printf '//\n'
        printf '`ifndef %s\n' "$guard"
        printf '`define %s\n\n' "$guard"
    } > "$STAGE/$hdr"

    for spec in "${ENV_MACRO_SPECS[@]}"; do
        [ -n "$spec" ] || continue
        macro="${spec%%@*}"
        src="${spec#*@}"
        [ -f "$UPSTREAM/$src" ] || rc_die "env-macro source '$src' not found upstream"
        line="$(grep -E "^[[:space:]]*\`define[[:space:]]+${macro}\b" "$UPSTREAM/$src" | head -1 || true)"
        [ -n "$line" ] || rc_die "macro '$macro' not found in $src"
        printf '// from %s\n' "$src" >> "$STAGE/$hdr"
        printf '%s\n\n' "$(printf '%s' "$line" \
            | sed -E "s/\`define[[:space:]]+${macro}\b/\`define ${MACRO_PREFIX}${macro}/")" >> "$STAGE/$hdr"
        rc_log "  env macro ${macro} -> ${MACRO_PREFIX}${macro} (from $src)"
    done

    printf '`endif // %s\n' "$guard" >> "$STAGE/$hdr"
    STAGED_FILES+=("$hdr")
    printf 'file\t(generated)\t%s\n' "$(basename "$hdr")" >> "$MAP"

    local old f
    for old in "${ENV_HEADER_REPLACE[@]}"; do
        [ -n "$old" ] || continue
        for f in "${STAGED_FILES[@]}"; do
            case "$f" in *.sv|*.svh|*.v) ;; *) continue ;; esac
            sed -i -E "s|(\`include[[:space:]]+\")${old}(\")|\1$(basename "$hdr")\2|g" "$STAGE/$f"
        done
        rc_log "  redirected \`include \"$old\" -> \"$(basename "$hdr")\""
    done
}

# ---------------------------------------------------------------------------
# rc_rename_files -- prefix every staged file name (the generated config header
#                    is already prefixed).
# ---------------------------------------------------------------------------
rc_rename_files() {
    local f dir base newbase new out=() n=0
    for f in "${STAGED_FILES[@]}"; do
        dir="$(dirname "$f")"
        base="$(basename "$f")"
        # Coverage binds and other non-synth delivery files keep upstream names.
        if ! rc_is_synth "$f"; then out+=("$f"); continue; fi
        case "$base" in
            "$PREFIX"*) out+=("$f"); continue ;;
        esac
        newbase="$(rc_renamed_basename "$base")"
        new="$dir/$newbase"
        [ -e "$STAGE/$new" ] && rc_die "rename collision: $new already exists"
        mv "$STAGE/$f" "$STAGE/$new"
        printf '%s\t%s\n' "$base" "$newbase" >> "$FILE_RENAMES"
        out+=("$new")
        n=$((n + 1))
    done
    STAGED_FILES=("${out[@]}")
    rc_log "renamed $n synthesizable file(s) of ${#STAGED_FILES[@]} delivered"
    rc_rename_collateral_files
}

# ---------------------------------------------------------------------------
# rc_rename_collateral_files -- collateral keeps its upstream names.
#
# Nothing here is synthesized, so nothing here can collide in the netlist and
# nothing here is renamed. File names, module names and the UVMF component
# names all stay exactly as upstream wrote them. The identifier pass has
# already rewritten their *references* to the renamed RTL, which is what makes
# the vendored bench bind to the vendored design.
#
# One exception survives, and it is forced rather than chosen. If a *synth*
# package happens to share its name with a directory, the identifier pass
# rewrites that name inside .f path strings just as readily as inside a
# declaration, so the directory has to follow or the filelist dangles. With the
# scope narrowed to RTL this is expected to fire zero times -- the UVMF package
# directories (ECC_in_pkg/ and friends) are named after UVMF packages, which
# are no longer renamed -- but the handling stays, because the alternative is a
# silent dangling path if a future block does declare such a package in rtl/.
# ---------------------------------------------------------------------------
rc_rename_collateral_files() {
    local f dir base new out=() nd=0 comp newdir comps=() root st
    local -A ident=() dirseen=()
    [ "${#COLLATERAL_FILES[@]}" -gt 0 ] || return 0

    # one pass over the map instead of a grep per file/component. The value is
    # the renamed identifier, not a flag: a directory that follows a renamed
    # package has to follow it to the name the map actually minted, which the
    # stem policy may have changed as well as the prefix.
    local newname
    while IFS=$'\t' read -r kind orig newname; do
        case "$kind" in module|package|interface) ident["$orig"]="$newname" ;; esac
    done < "$MAP"

    for f in "${COLLATERAL_FILES[@]}" "${COLLATERAL_BINARIES[@]}"; do
        dir="$(dirname "$f")"; base="$(basename "$f")"

        # Directory components named after a renamed identifier follow it --
        # but only *below* the declared subtree root. src/hmac/ and
        # src/hmac_drbg/ are block directories that happen to share a name with
        # a module; renaming them would break the mirrored hierarchy, and the
        # directory name is already a separate knob (BLOCK_DIR/DEST_SUBTREES).
        # $f is a *destination* path, so the roots to match against are the
        # destination subtrees. For every block but ABR those are the upstream
        # paths unchanged; for ABR they are not, and matching the upstream list
        # found no root at all -- which made the whole path eligible, and renamed
        # the adams-bridge unit directories (ntt_top/, decompose/, ...) after the
        # modules they happen to share a name with.
        root=""
        for st in "${COLLATERAL_DIRS[@]}"; do
            case "$f" in "$st"/*) [ "${#st}" -gt "${#root}" ] && root="$st" ;; esac
        done
        newdir="$root"
        IFS='/' read -r -a comps <<< "${dir#"$root"}"
        for comp in "${comps[@]}"; do
            [ -n "$comp" ] || continue
            case "$comp" in
                "$PREFIX"*) : ;;
                *) [ -n "${ident[$comp]:-}" ] && comp="${ident[$comp]}" ;;
            esac
            newdir="${newdir:+$newdir/}$comp"
        done
        if [ "$newdir" != "$dir" ] && [ -z "${dirseen[$newdir]:-}" ]; then
            dirseen["$newdir"]=1; nd=$((nd + 1))
        fi

        new="$newdir/$base"

        if [ "$new" != "$f" ]; then
            [ -e "$STAGE/$new" ] && rc_die "collateral rename collision: $new"
            mkdir -p "$STAGE/$(dirname "$new")"
            mv "$STAGE/$f" "$STAGE/$new"
        fi
        out+=("$new")
    done

    COLLATERAL_INSTALLED=("${out[@]}")
    # moving the last file out of a renamed directory leaves the old one behind
    find "$STAGE" -type d -empty -delete
    if [ "$nd" -gt 0 ]; then
        rc_log "collateral: $nd directory name(s) followed a renamed RTL package, ${#out[@]} file name(s) kept upstream"
    else
        rc_log "collateral: all ${#out[@]} file name(s) kept upstream"
    fi
}

# ---------------------------------------------------------------------------
# rc_fix_file_references -- after collateral files are renamed, rewrite every
# reference to them by name.
#
# The identifier pass cannot do this: a reference to
# "fv_add_sub_alter_coverpoints.sv" is a *file* name, not an identifier, and
# the stem is not in the map. Matching the name together with its extension
# keeps the substitution tight; the look-behind excludes identifier characters
# so an already-prefixed "tessera_fv_...sv" cannot match again (idempotent).
#
# Scope is every text file in both tiers: `include directives, formal .f lists,
# compile.do / tcl scripts and Makefiles all name files.
# ---------------------------------------------------------------------------
rc_fix_file_references() {
    local n
    [ -s "$FILE_RENAMES" ] || return 0
    n="$(wc -l < "$FILE_RENAMES")"
    perl -e '
        my ($mapfile, @files) = @ARGV;
        open(my $m, "<", $mapfile) or die $!;
        my %r;
        while (<$m>) { chomp; my ($o, $n) = split /\t/; $r{$o} = $n if defined $n; }
        close $m;
        exit 0 unless %r;
        my $alt = join "|", map { quotemeta } sort { length($b) <=> length($a) } keys %r;
        my $re  = qr/(?<![A-Za-z0-9_])($alt)/;
        for my $f (@files) {
            open(my $in, "<", $f) or next;
            local $/; my $txt = <$in>; close $in;
            my $orig = $txt;
            $txt =~ s/$re/$r{$1}/g;
            next if $txt eq $orig;
            open(my $out, ">", $f) or die $!;
            print $out $txt; close $out;
        }
    ' "$FILE_RENAMES" \
      $(printf "$STAGE/%s " "${STAGED_FILES[@]}") \
      $(printf "$STAGE/%s " "${COLLATERAL_INSTALLED[@]}")
    rc_log "rewrote references to $n renamed file name(s)"
}

# ---------------------------------------------------------------------------
# rc_fix_path_components -- undo the identifier pass where it hit a *directory*
# name inside a path string.
#
# The identifier pass is a text pass: it cannot tell
#
#     hmac_drbg          <- the module, must become tessera_hmac_drbg
#     src/hmac_drbg/rtl  <- the directory, must stay put
#
# apart, because several blocks name their top module after their folder. Left
# alone it emits dangling paths like
#
#     ${CALIPTRA_ROOT}/src/tessera_hmac_drbg/rtl/tessera_hmac_drbg.sv
#                          ^^^^^ no such directory      ^^^^^ correct
#
# in .vf lists, compile.do scripts and stimulus YAML. Nothing else catches
# these: check_filelists.sh skips ${CALIPTRA_ROOT}-rooted entries as external
# references, and the round-trip strips the prefix before diffing, so the
# dangling form compares equal to upstream.
#
# The repair is driven by the tree we actually produced rather than by the
# rename map, which is what makes it safe: a prefixed path component is
# reverted only when the unprefixed directory exists and the prefixed one does
# not. If a directory really was renamed (a synth package naming its own
# folder), the prefixed directory exists and we leave the reference alone.
# ---------------------------------------------------------------------------
rc_fix_path_components() {
    local d base keep=() rc_unstem=() n=0
    # Directory names come from the upstream checkout as well as our own stage:
    # a block may reference a sibling block's folder (ECC compiles hmac_drbg's
    # RTL) that this driver never staged, and those references are exactly the
    # ones most likely to dangle.
    while IFS= read -r d; do
        base="$(basename "$d")"
        case "$base" in "${PREFIX}"*) continue ;; esac
        [ -d "$(dirname "$d")/${PREFIX}${base}" ] && continue
        find "$STAGE" -type d -name "${PREFIX}${base}" -print -quit | grep -q . && continue
        keep+=("$base")
    done < <({ find "$STAGE" -type d; find "$UPSTREAM/src" -maxdepth 2 -type d; } | sort -u)
    # Names that are directories somewhere *outside* both trees. OpenTitan-derived
    # blocks cite their original home in comments and doc URLs -- sha3/rtl/kmac.sv
    # links to .../hw/ip/kmac/doc/... -- and kmac is a module here, not a folder,
    # so nothing in either checkout can tell the reverter to leave it alone.
    keep+=("${EXTRA_PATH_DIRS[@]}")
    # A stem rename makes the mangle two layers deep, so stripping the prefix is
    # not enough to land back on a real name. Upstream `src/hmac` becomes the
    # path component `tessera_hmac512`: prefix *and* stem. Reverting that to
    # `hmac512` only resolved while the Tessera directory happened to be spelled
    # `src/hmac512` too -- a coincidence, and one that dies the moment the block
    # is shelved under a different directory name. Map it back to the upstream
    # name instead, which is what these ${CALIPTRA_ROOT}-rooted citations mean:
    # they point into a caliptra-rtl checkout, not into this tree.
    local spec from to
    for spec in "${STEM_RENAMES[@]}"; do
        from="${spec%%=*}"; to="${spec#*=}"
        [ -n "$from" ] && [ -n "$to" ] && [ "$from" != "$to" ] || continue
        [ -d "$UPSTREAM/src/$from" ] || continue
        rc_unstem+=("$to=$from")
    done
    [ "${#keep[@]}" -gt 0 ] || return 0
    n="$(perl -e '
        my ($prefix, $nkeep, @rest) = @ARGV;
        my @keep   = splice(@rest, 0, $nkeep);
        my $nunstem = shift @rest;
        my @unstem = splice(@rest, 0, $nunstem);
        my @files  = @rest;
        my %seen; my @u = grep { !$seen{$_}++ } @keep;
        my $alt = join "|", map { quotemeta } sort { length($b) <=> length($a) } @u;
        my $p   = quotemeta $prefix;
        # only between path separators: a bare identifier is never touched
        my $re  = qr{(?<=/)$p($alt)(?=/)};
        # stem-renamed components, longest first so a longer stem cannot be
        # shadowed by a prefix of itself
        my %un = map { my ($k,$v) = split /=/, $_, 2; ($k => $v) } @unstem;
        my $ualt = join "|", map { quotemeta } sort { length($b) <=> length($a) } keys %un;
        my $ure  = $ualt ? qr{(?<=/)$p($ualt)(?=/)} : undef;
        my $hits = 0;
        for my $f (@files) {
            open(my $in, "<", $f) or next;
            local $/; my $txt = <$in>; close $in;
            my $orig = $txt;
            $hits += ($txt =~ s/$ure/$un{$1}/g) if $ure;
            $hits += ($txt =~ s/$re/$1/g);
            next if $txt eq $orig;
            open(my $out, ">", $f) or die $!;
            print $out $txt; close $out;
        }
        print $hits;
    ' "$PREFIX" "${#keep[@]}" "${keep[@]}" \
      "${#rc_unstem[@]}" ${rc_unstem[0]:+"${rc_unstem[@]}"} \
      $(printf "$STAGE/%s " "${STAGED_FILES[@]}") \
      $(printf "$STAGE/%s " "${COLLATERAL_INSTALLED[@]}"))"
    [ "$n" -gt 0 ] && rc_log "reverted $n prefixed path component(s) naming an unrenamed directory"
    return 0
}

# ---------------------------------------------------------------------------
# rc_emit_filelist -- compile-ordered filelist.
#
# It lands in the block's config/ directory, mirroring where caliptra-rtl keeps
# its own .vf filelists (src/ecc/config/ecc_top.vf -> src/ecc/config/tessera_ecc_top.vf).
#
# The order is derived from the upstream .vf filelist when the driver provides
# one; the imported block keeps the upstream package/module compile order and
# we do not have to reinvent it. Files not mentioned upstream are appended.
# ---------------------------------------------------------------------------
rc_emit_filelist() {
    local ordered=() f base line vf_base incdirs=() d
    vf_base="${VF_FILELIST:+$(basename "$VF_FILELIST")}"
    vf_base="${vf_base:-$BLOCK.vf}"
    FILELIST="$CONFIG_DIR/$(rc_renamed_basename "$vf_base")"

    if [ -n "${VF_FILELIST:-}" ] && [ -f "$UPSTREAM/$VF_FILELIST" ]; then
        while IFS= read -r line; do
            base="$(basename "${line%%[[:space:]]*}")"
            # synthesizable sources were prefixed; anything else kept its name
            f="$(rc_staged_path "$(rc_renamed_basename "$base")")"
            [ -n "$f" ] || f="$(rc_staged_path "$base")"
            [ -n "$f" ] || continue
            case " ${ordered[*]} " in *" $f "*) continue ;; esac
            ordered+=("$f")
        done < <(grep -E "${VF_FILTER:-.}" "$UPSTREAM/$VF_FILELIST" | grep -vE '^\s*(\+|//|$)')
        rc_log "compile order derived from $VF_FILELIST"
    fi

    # The generated config header must be visible before anything uses it.
    if [ -n "${ENV_HEADER:-}" ]; then
        ordered=("$ENV_HEADER" "${ordered[@]}")
    fi

    # Anything staged but not named upstream is appended -- but only if it is
    # actually a compilation unit. Two kinds of staged file are not:
    #
    #   * non-HDL. A block's rtl/ can hold plain data (aes ships an
    #     `aes_rev_info` text file recording the OpenTitan commit it came from)
    #     and handing that to a parser is a syntax error.
    #   * headers. A .svh/.vh is an include target, reached through the
    #     +incdir+ lines above, not a file to compile on its own. Upstream's
    #     filelist is the authority on which ones are an exception -- hmac256
    #     ships hmac256_reg_sample.svh, a UVM register-model fragment whose
    #     class bodies only resolve inside the UVM tier, and upstream
    #     deliberately leaves it out of the RTL compile order. If we append it
    #     anyway the block no longer elaborates. ENV_HEADER is the one header
    #     we add ourselves, and it is prepended above rather than appended.
    for f in "${STAGED_FILES[@]}"; do
        case "$f" in *.sv|*.v) ;; *) continue ;; esac
        case " ${ordered[*]} " in *" $f "*) continue ;; esac
        ordered+=("$f")
    done

    for d in "${DEST_SUBTREES[@]}"; do
        case " ${incdirs[*]} " in *" $d "*) continue ;; esac
        incdirs+=("$d")
    done

    mkdir -p "$STAGE/$CONFIG_DIR"
    {
        printf '// GENERATED by tools/scripts/rename/rename_%s.sh -- do not edit by hand.\n' "$BLOCK"
        printf '// Compile-ordered filelist for the imported %s block.\n' "$BLOCK"
        printf '// Set TESSERA_ROOT to the root of this repository.\n'
        for d in "${incdirs[@]}"; do
            printf '+incdir+${TESSERA_ROOT}/%s\n' "$d"
        done
        for f in "${ordered[@]}"; do
            [ -n "$f" ] || continue
            printf '${TESSERA_ROOT}/%s\n' "$f"
        done
    } > "$STAGE/$FILELIST"
    rc_log "wrote $FILELIST"
}

# Resolve a renamed basename back to its staged, repo-relative path.
rc_staged_path() {
    local want="$1" f
    for f in "${STAGED_FILES[@]}"; do
        if [ "$(basename "$f")" = "$want" ]; then printf '%s' "$f"; return 0; fi
    done
    return 0
}

# ---------------------------------------------------------------------------
# rc_install -- publish the staged block and its map into the Tessera repo
# ---------------------------------------------------------------------------
rc_install() {
    local d
    INSTALLED_FILES=()
    for d in "${DEST_SUBTREES[@]}" "${COLLATERAL_DIRS[@]}" "$CONFIG_DIR"; do
        rc_check_relpath "$d"
        rm -rf "${DEST:?}/$d"
    done
    mkdir -p "$DEST"
    cp -a "$STAGE"/. "$DEST"/

    local f
    while IFS= read -r f; do
        INSTALLED_FILES+=("${f#./}")
    done < <(cd "$STAGE" && find . -type f | sed 's|^\./||' | sort)

    grep -vE '^\s*#' "$MAP" > "$OUT_REVINFO/revinfo.map" || true
    sed -i "1i # Tessera identifier rename map for block '$BLOCK' (prefix: $PREFIX)" "$OUT_REVINFO/revinfo.map"
    rc_log "installed -> $(printf '%s ' "${DEST_SUBTREES[@]}")and $BLOCK_DIR/revinfo.map"
}

# ---------------------------------------------------------------------------
# rc_emit_revinfo -- provenance record.
#
# Purpose (per the engineering lead): make it possible to review the upstream
# changelog when pulling updates, and to reproduce the import exactly.
# ---------------------------------------------------------------------------
# The changelog hint has to be per repository, not per block: for ABR most
# of the recorded subtrees live in adams-bridge, and `git log` in the
# superproject would only show the gitlink moving, never the RTL.
rc_review_hints() {
    local i s sp rest unclaimed=() claimed sbranch ssha
    for s in "${UPSTREAM_SUBTREES[@]}"; do
        claimed=0
        for i in "${!SUBMODULE_PATHS[@]}"; do
            sp="${SUBMODULE_PATHS[$i]}"
            case "$s" in "$sp"/*) claimed=1; break ;; esac
        done
        [ "$claimed" -eq 1 ] || unclaimed+=("$s")
    done
    printf '# To review what changed upstream since this import:\n'
    if [ "${#unclaimed[@]}" -gt 0 ]; then
        printf '#   git -C <caliptra-rtl> log --oneline %s..origin/%s -- %s\n' \
               "$UPSTREAM_SHA" "$UPSTREAM_BRANCH" "$(printf '%s ' "${unclaimed[@]}")"
    fi
    for i in "${!SUBMODULE_PATHS[@]}"; do
        sp="${SUBMODULE_PATHS[$i]}"
        rest=()
        for s in "${UPSTREAM_SUBTREES[@]}"; do
            case "$s" in "$sp"/*) rest+=("${s#"$sp"/}") ;; esac
        done
        [ "${#rest[@]}" -gt 0 ] || continue
        sbranch="${SUBMODULE_BRANCHES[$i]:-main}"
        ssha="$(git -C "$UPSTREAM/$sp" rev-parse HEAD)"
        printf '#   git -C <%s> log --oneline %s..origin/%s -- %s\n' \
               "$(basename "$sp")" "$ssha" "$sbranch" "$(printf '%s ' "${rest[@]}")"
    done
}

rc_emit_revinfo() {
    local out="$OUT_REVINFO/revinfo.yml"
    local f tok script_sha src_n ren_n
    # Hash the *contents* only. sha256sum prints the path next to each digest,
    # so feeding its output back in would make the fingerprint depend on how the
    # script was invoked ("./tools/.../rename_ecc.sh" vs an absolute path from
    # import_block.sh) rather than on the toolchain, and a re-import would not
    # reproduce.
    script_sha="$(cat "$0" "$RC_LIB_DIR/rename_common.sh" "$RC_LIB_DIR/lib/apply_map.pl" \
                  | sha256sum | cut -d' ' -f1)"

    # What the import produced that upstream has no counterpart for. This is the
    # only part of the file list that cannot be recovered by looking at the
    # committed tree: every other file under source_dirs/collateral_dirs maps
    # back to an upstream path by undoing the prefix and the stem, which is
    # exactly what roundtrip_check does. Declaring the generated files lets that
    # check demand an upstream counterpart for everything else.
    local generated=()
    [ -n "${FILELIST:-}" ]   && generated+=("$FILELIST")
    [ -n "${ENV_HEADER:-}" ] && generated+=("$ENV_HEADER")
    # A generated path that is not actually installed would silently excuse a
    # file from the roundtrip proof, so assert the declaration is truthful.
    # Done in-shell rather than with `printf ... | grep -q`: grep exits on the
    # first match, printf then takes SIGPIPE, and under `set -o pipefail` a
    # *successful* match would come back as a failed pipeline.
    local inst found
    for tok in ${generated[@]+"${generated[@]}"}; do
        found=0
        for inst in ${INSTALLED_FILES[@]+"${INSTALLED_FILES[@]}"}; do
            [ "$inst" = "$tok" ] && { found=1; break; }
        done
        [ "$found" -eq 1 ] || rc_die "declared generated artifact '$tok' was not installed"
    done

    src_n="$(grep -c . "$SRC_MANIFEST" || true)"
    ren_n="${#INSTALLED_FILES[@]}"

    {
        printf '# Tessera vendored-block provenance record -- GENERATED, do not edit by hand.\n'
        printf '#\n'
        rc_review_hints
        printf '#\n'
        printf 'block: %s\n' "$BLOCK"
        printf 'prefix: "%s"\n' "$PREFIX"
        printf 'macro_prefix: "%s"\n' "$MACRO_PREFIX"
        printf 'imported_at: "%s"\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf '\n'
        printf 'upstream:\n'
        printf '  repo: "%s"\n' "$UPSTREAM_URL"
        printf '  branch: "%s"\n' "$UPSTREAM_BRANCH"
        printf '  commit: "%s"\n' "$UPSTREAM_SHA"
        printf '  commit_date: "%s"\n' "$UPSTREAM_DATE"
        printf '  commit_subject: "%s"\n' "$(printf '%s' "$UPSTREAM_DESC" | sed 's/"/\\"/g')"
        printf '  working_tree_dirty: %s\n' "$UPSTREAM_DIRTY"
        if [ "${#SUBMODULE_PATHS[@]}" -gt 0 ]; then
            printf '  submodules:  # vendored from a different repository than the one above\n'
            local i sp surl sbr ssha sdate ssubj sdirty glink
            for i in "${!SUBMODULE_PATHS[@]}"; do
                sp="${SUBMODULE_PATHS[$i]}"
                surl="$(git -C "$UPSTREAM/$sp" config --get remote.origin.url 2>/dev/null || echo unknown)"
                sbr="${SUBMODULE_BRANCHES[$i]:-$UPSTREAM_BRANCH}"
                ssha="$(git -C "$UPSTREAM/$sp" rev-parse HEAD)"
                sdate="$(git -C "$UPSTREAM/$sp" log -1 --format=%cI)"
                ssubj="$(git -C "$UPSTREAM/$sp" log -1 --format=%s | sed 's/"/\\"/g')"
                if [ -n "$(git -C "$UPSTREAM/$sp" status --porcelain)" ]; then sdirty=true; else sdirty=false; fi
                # What the superproject pins, which is normally the same commit.
                # Recording both is what makes a deliberate override legible:
                # otherwise a reader has no way to tell a pin from a drift.
                glink="$(git -C "$UPSTREAM" rev-parse "HEAD:$sp" 2>/dev/null || echo unknown)"
                printf '    - path: "%s"\n' "$sp"
                printf '      repo: "%s"\n' "$surl"
                printf '      branch: "%s"\n' "$sbr"
                printf '      commit: "%s"\n' "$ssha"
                printf '      commit_date: "%s"\n' "$sdate"
                printf '      commit_subject: "%s"\n' "$ssubj"
                printf '      working_tree_dirty: %s\n' "$sdirty"
                printf '      superproject_gitlink: "%s"' "$glink"
                if [ "$glink" = "$ssha" ]; then
                    printf '\n'
                else
                    printf '  # vendored ahead of the gitlink, see SUBMODULE_COMMITS\n'
                fi
            done
        fi
        printf '  subtrees:  # upstream path -> Tessera path\n'
        local i
        for i in "${!UPSTREAM_SUBTREES[@]}"; do
            printf '    - { upstream: "%s", tessera: "%s" }\n' \
                   "${UPSTREAM_SUBTREES[$i]}" "${DEST_SUBTREES[$i]}"
        done
        if [ "${#COLLATERAL_SUBTREES[@]}" -gt 0 ]; then
            printf '  collateral_subtrees:  # upstream path -> Tessera path\n'
            for i in "${!COLLATERAL_SUBTREES[@]}"; do
                [ -n "${COLLATERAL_SUBTREES[$i]}" ] || continue
                printf '    - { upstream: "%s", tessera: "%s" }\n' \
                       "${COLLATERAL_SUBTREES[$i]}" "${COLLATERAL_DEST_SUBTREES[$i]:-${COLLATERAL_SUBTREES[$i]}}"
            done
        fi
        if [ -n "${VF_FILELIST:-}" ]; then
            printf '  compile_order_from: %s\n' "$VF_FILELIST"
        fi
        printf '\n'
        printf 'importer:\n'
        printf '  script: tools/scripts/rename/%s\n' "$(basename "$0")"
        printf '  library_version: "%s"\n' "$RC_SCRIPT_VERSION"
        printf '  toolchain_fingerprint: "%s"\n' "$script_sha"
        printf '  bash: "%s"\n' "${BASH_VERSION}"
        printf '  perl: "%s"\n' "$(perl -e 'print $^V')"
        printf '\n'
        printf 'policy:\n'
        printf '  rename_scope: "synthesized design material only"\n'
        printf '  stem_renames:  # block-name stems rewritten under the prefix (repo-wide)\n'
        if [ "${#STEM_RENAMES[@]}" -gt 0 ]; then
            for tok in "${STEM_RENAMES[@]}"; do [ -n "$tok" ] && printf '    - "%s"\n' "$tok"; done
        else
            printf '    []\n'
        fi
        printf '  stem_keep:  # names that merely share the leading token and keep it\n'
        if [ "${#STEM_KEEP[@]}" -gt 0 ]; then
            for tok in "${STEM_KEEP[@]}"; do [ -n "$tok" ] && printf '    - "%s"\n' "$tok"; done
        else
            printf '    []\n'
        fi
        printf '  synth_subtrees:  # identifiers declared here are renamed; everything else only references them\n'
        for tok in "${SYNTH_SUBTREES[@]}"; do [ -n "$tok" ] && printf '    - "%s"\n' "$tok"; done
        printf '  excluded_globs:\n'
        for tok in "${EXCLUDE_GLOBS[@]}"; do [ -n "$tok" ] && printf '    - "%s"\n' "$tok"; done
        printf '  artifact_globs:  # build/sim outputs, regenerated not vendored\n'
        for tok in "${ARTIFACT_GLOBS[@]}"; do [ -n "$tok" ] && printf '    - "%s"\n' "$tok"; done
        printf '  cross_block_identifiers:\n'
        if [ "${#EXTRA_RENAME_IDENTS[@]}" -gt 0 ]; then
            for tok in "${EXTRA_RENAME_IDENTS[@]}"; do [ -n "$tok" ] && printf '    - "%s"\n' "$tok"; done
        else
            printf '    []\n'
        fi
        printf '  environment_config_macros:\n'
        if [ "${#ENV_MACRO_SPECS[@]}" -gt 0 ]; then
            for tok in "${ENV_MACRO_SPECS[@]}"; do [ -n "$tok" ] && printf '    - "%s"\n' "$tok"; done
        else
            printf '    []\n'
        fi
        printf '  generator_inputs:  # fed to a code generator, must stay byte-identical to upstream\n'
        if [ "${#GENERATOR_INPUTS[@]}" -gt 0 ]; then
            for tok in "${GENERATOR_INPUTS[@]}"; do [ -n "$tok" ] && printf '    - "%s"\n' "$tok"; done
        else
            printf '    []\n'
        fi
        printf '  keep_list:  # shared Tessera platform identifiers, deliberately NOT prefixed\n'
        if [ "${#KEEP_IDENTS[@]}" -gt 0 ]; then
            for tok in "${KEEP_IDENTS[@]}"; do [ -n "$tok" ] && printf '    - "%s"\n' "$tok"; done
        else
            printf '    []\n'
        fi
        printf '\n'
        printf 'artifacts:\n'
        printf '  block_dir: %s\n' "$BLOCK_DIR"
        printf '  source_dirs:\n'
        for tok in "${DEST_SUBTREES[@]}"; do printf '    - %s\n' "$tok"; done
        if [ "${#COLLATERAL_DIRS[@]}" -gt 0 ]; then
            printf '  collateral_dirs:  # imported whole, looser rename contract\n'
            for tok in "${COLLATERAL_DIRS[@]}"; do printf '    - %s\n' "$tok"; done
        else
            printf '  collateral_dirs: []\n'
        fi
        printf '  filelist: %s\n' "$FILELIST"
        printf '  rename_map: %s/revinfo.map\n' "$BLOCK_DIR"
        printf '  generated:  # produced by the import; no upstream counterpart\n'
        if [ "${#generated[@]}" -gt 0 ]; then
            for tok in "${generated[@]}"; do printf '    - %s\n' "$tok"; done
        else
            printf '    []\n'
        fi
        printf '\n'
        printf 'content:  # engine-level summary; the file list is the committed tree itself\n'
        printf '  source_files: %s\n' "$src_n"
        printf '  renamed_files: %s\n' "$ren_n"
    } > "$out"
    rc_log "wrote $BLOCK_DIR/revinfo.yml"
}

# ---------------------------------------------------------------------------
# rc_run -- orchestration
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# rc_check_generator_inputs -- enforce the stronger contract on generator inputs
#
# Everything else in the block is held to "differs from upstream by naming
# only". These files are held to "byte-identical to upstream", because they are
# read by a code generator rather than compiled: if they were renamed, the next
# regeneration would emit names that disagree with what is committed, and the
# round-trip check could not tell (it strips the prefix before comparing).
#
# Generator inputs are declared by their upstream path; the committed copy is
# at rc_gi_dest of that, which differs only for a block that relocates its
# collateral.
# ---------------------------------------------------------------------------
rc_check_generator_inputs() {
    [ "${#GENERATOR_INPUTS[@]}" -gt 0 ] || return 0
    [ "$WITH_COLLATERAL" -eq 1 ] || return 0
    local gi dst n=0 i
    for i in "${!GENERATOR_INPUTS[@]}"; do
        gi="${GENERATOR_INPUTS[$i]}"
        [ -n "$gi" ] || continue
        dst="${GENERATOR_INPUTS_DEST[$i]}"
        rc_check_relpath "$gi"
        rc_check_relpath "$dst"
        [ -f "$UPSTREAM/$gi" ] || rc_die "generator input '$gi' not present upstream"
        [ -f "$DEST/$dst" ] || rc_die "generator input '$gi' was not imported (expected at $dst)"
        cmp -s "$UPSTREAM/$gi" "$DEST/$dst" || \
            rc_die "generator input '$gi' was modified; it must stay byte-identical to upstream"
        n=$((n + 1))
    done
    rc_log "generator inputs byte-identical to upstream ($n file(s))"
}

rc_run() {
    rc_position_submodules
    rc_stage
    rc_stage_collateral
    if declare -F block_pre_rename >/dev/null; then block_pre_rename; fi
    rc_build_map
    rc_apply
    rc_env_macros
    if declare -F block_post_rename >/dev/null; then block_post_rename; fi
    rc_rename_files
    # Both fixups undo over-reach of the identifier pass, and both apply to the
    # delivery tier as much as to the collateral tier. They used to hang off the
    # end of the collateral pass, which meant a block with no collateral (sha3,
    # aes) silently skipped them -- and those are exactly the OpenTitan-derived
    # blocks whose comments cite upstream paths like hw/ip/aes/pre_sca.
    rc_hold_out_generator_inputs
    rc_fix_file_references
    rc_fix_path_components
    rc_restore_generator_inputs
    rc_emit_filelist
    rc_install
    rc_check_generator_inputs
    rc_emit_revinfo
    "$RC_LIB_DIR/verify_import.sh" --dest "$DEST" --block "$BLOCK" --prefix "$PREFIX"
    rc_log "import complete"
}
