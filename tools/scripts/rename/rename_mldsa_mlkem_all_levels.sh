#!/usr/bin/env bash
#
# rename_mldsa_mlkem_all_levels.sh -- import + prefix the Adams Bridge PQC
# engine, which implements ML-DSA and ML-KEM at every parameter set.
#
#   ./tools/scripts/rename/rename_mldsa_mlkem_all_levels.sh --upstream /path/to/caliptra-rtl
#
# The Tessera directory is named for what the engine implements rather than for
# its upstream codename: upstream calls it "abr" (Adams Bridge), which says
# nothing about ML-DSA, ML-KEM, or the security levels it covers.
#
# The directory name and the identifier stem are deliberately different knobs.
# The directory is mldsa_mlkem_all_levels; the identifiers keep the short
# upstream abr_ stem, so modules stay tessera_abr_top rather than growing a
# 22-character prefix across all 222 of them. See the stem policy in
# rename_common.sh for the case where the two are tied together instead.
#
# The one block that is not a caliptra-rtl directory
# --------------------------------------------------
# Every other engine here lives entirely inside caliptra-rtl. ABR does not. In
# caliptra-rtl, src/abr/ holds four files -- a compile spec and a coverage bind --
# and the ~160 RTL files live in a separate repository, chipsalliance/adams-bridge,
# wired in as the git submodule submodules/adams-bridge.
#
# Tessera does not carry that split: the engineering decision was to keep ABR as a
# normal src/<block>/ tree like every other engine. So this driver flattens two
# repositories into one Tessera block:
#
#   caliptra-rtl    src/abr/coverage/        -> src/mldsa_mlkem_all_levels/coverage/
#   adams-bridge    src/<unit>/rtl/          -> src/mldsa_mlkem_all_levels/<unit>/rtl/
#   adams-bridge    src/abr_top/coverage/    -> src/mldsa_mlkem_all_levels/abr_top/coverage/
#
# That flattening costs us something real, and the cost is paid in revinfo.
# Every other block's provenance is one commit. ABR's is two, and the second one
# is the one that actually matters -- caliptra-rtl's submodule pointer can sit
# still for months while adams-bridge moves. SUBMODULE_PATHS makes the engine
# record the adams-bridge HEAD as its own provenance entry, so
#
#   git -C <adams-bridge> log --oneline <recorded sha>..origin/main
#
# answers "what changed since we vendored this" for the sources we actually
# shipped, not for the pointer to them.
#
# Why the unit directories survive the flattening
# -----------------------------------------------
# adams-bridge is 25 units, each with its own rtl/. They could have been poured
# into one src/mldsa_mlkem_all_levels/rtl/, and that would have been simpler. They are not, because
# the per-unit `include directories are load-bearing: abr_top.vf carries 26
# +incdir+ lines, one per unit, and the sources `include across unit boundaries
# by bare filename. Collapsing the tree would silently change which file an
# `include resolves to. Keeping the hierarchy means the generated filelist's
# +incdir+ set is a mechanical translation of upstream's.
#
# Other block-specific notes
# --------------------------
# * Compile order comes from adams-bridge's own abr_top.vf. Its paths are
#   ${ADAMSBRIDGE_ROOT}-rooted rather than ${CALIPTRA_ROOT}-rooted, which costs
#   nothing: rc_emit_filelist matches on basenames, not on path prefixes.
# * The submodule sits *inside* the caliptra-rtl checkout, so every path here is
#   still an ordinary $UPSTREAM-relative path and no new staging machinery is
#   needed -- only the provenance record had to learn about it.
# * abr_prim/lint/ is skipped, like aes/lint/ and hmac's rtl_lint waiver: tool
#   configuration, not source.
# * No EXTRA_RENAME_IDENTS. ABR vendors its own copies of the primitives
#   (abr_prim, abr_prim_generic) and its own Keccak (abr_sha3) rather than
#   sharing caliptra-rtl's, so it has no cross-block references to rewrite --
#   it is the only leaf in the dependency matrix.

set -euo pipefail

BLOCK="mldsa_mlkem_all_levels"

# Normally the block directory is inferred as the parent of the first delivery
# subtree. Here that parent is <block>/abr_libs, the first adams-bridge unit, not
# the block root -- this is the only block whose delivery subtrees are two levels
# down rather than one. Say it explicitly.
BLOCK_DIR="src/mldsa_mlkem_all_levels"

# The adams-bridge units, in the repository's own order. Each contributes rtl/
# to the delivery tier and whatever of tb/ stimulus/ uvmf/ utb/ it has to the
# collateral tier.
ABR_UNITS=(
    abr_libs abr_prim abr_prim_generic abr_sampler_top abr_sha3 abr_top
    barrett_reduction cbd_sampler compress decompose decompress exp_mask
    makehint norm_check ntt_top pk_decode power2round rej_bounded rej_sampler
    sample_in_ball sigdecode_h sig_decode_z sig_encode_z sk_decode sk_encode
)

SUBMODULE_PATHS=("submodules/adams-bridge")
# ABR's sources move in adams-bridge faster than caliptra-rtl bumps the gitlink
# at them, and Tessera ships the multi-security-level parameter sets
# (ML-DSA-44/65, ML-KEM-512/768) that the pinned commit predates. So this block
# is vendored from a named adams-bridge branch rather than from the gitlink.
# Declaring it here rather than just checking it out by hand is what keeps the
# import reproducible: rc_position_submodules enacts it, so a re-import after a
# plain `git submodule update` still lands on the same RTL.
#
# Delete these two lines once caliptra-rtl's gitlink has caught up -- an empty
# SUBMODULE_COMMITS entry means "follow the gitlink", which is where every other
# submodule-backed import should be.
SUBMODULE_BRANCHES=("user/mojtabab/abr-security-levels/config-and-units")
SUBMODULE_COMMITS=("a2bfbed1b4d85d908d6e261b9c856d2c08664682")
SUB="submodules/adams-bridge"

UPSTREAM_SUBTREES=()
DEST_SUBTREES=()
COLLATERAL_SUBTREES=()

for u in "${ABR_UNITS[@]}"; do
    UPSTREAM_SUBTREES+=("$SUB/src/$u/rtl")
    DEST_SUBTREES+=("$BLOCK_DIR/$u/rtl")
done

# Which units ship which collateral is listed rather than discovered, because
# the driver is evaluated before --upstream is parsed and because a unit quietly
# losing its bench upstream should show up as a diff in this file, not as a
# smaller import nobody noticed. abr_prim, abr_prim_generic, abr_sampler_top and
# decompress have no bench at all; only abr_libs and abr_top carry a UVMF
# environment; ntt_top alone has a second, unit-level bench in utb/.
ABR_TB_UNITS=(
    abr_libs abr_sha3 abr_top barrett_reduction cbd_sampler compress decompose
    exp_mask makehint norm_check ntt_top pk_decode power2round rej_bounded
    rej_sampler sample_in_ball sigdecode_h sig_decode_z sig_encode_z sk_decode
    sk_encode
)
ABR_STIMULUS_UNITS=(
    abr_libs abr_sha3 abr_top cbd_sampler compress decompose exp_mask makehint
    norm_check ntt_top pk_decode power2round rej_bounded rej_sampler
    sample_in_ball sigdecode_h sig_decode_z sig_encode_z sk_decode sk_encode
)
ABR_UVMF_UNITS=(abr_libs abr_top)
ABR_UTB_UNITS=(ntt_top)

COLLATERAL_DEST_SUBTREES=()
abr_collateral() {
    local u
    for u in "$@"; do
        COLLATERAL_SUBTREES+=("$SUB/src/$u/$COLL")
        COLLATERAL_DEST_SUBTREES+=("$BLOCK_DIR/$u/$COLL")
    done
}
COLL=tb       abr_collateral "${ABR_TB_UNITS[@]}"
COLL=stimulus abr_collateral "${ABR_STIMULUS_UNITS[@]}"
COLL=uvmf     abr_collateral "${ABR_UVMF_UNITS[@]}"
COLL=utb      abr_collateral "${ABR_UTB_UNITS[@]}"

# caliptra-rtl's own ABR material: the coverage bind that ties the engine into
# the Caliptra top level, plus adams-bridge's own coverage. Both are delivery
# tier but not synthesizable, so like every other coverage/ here they keep their
# file names and only have references rewritten.
UPSTREAM_SUBTREES+=("src/abr/coverage" "$SUB/src/abr_top/coverage")
DEST_SUBTREES+=("$BLOCK_DIR/coverage" "$BLOCK_DIR/abr_top/coverage")
COLLATERAL_SUBTREES+=("src/abr/coverage/config")
COLLATERAL_DEST_SUBTREES+=("$BLOCK_DIR/coverage/config")

VF_FILELIST="$SUB/src/abr_top/config/abr_top.vf"
VF_FILTER="/rtl/"

EXCLUDE_GLOBS=(
    "*_reg_uvm.sv"
    "*.rdl"
)

EXTRA_RENAME_IDENTS=()
EXTRA_PATH_DIRS=()
ENV_MACRO_SPECS=()
ENV_HEADER_REPLACE=()
GENERATOR_INPUTS=()

KEEP_IDENTS=(
    "kv_defines_pkg"
    "kv_read_t"
    "kv_write_t"
    "kv_error_code_e"
    "uvm_pkg"
)

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/rename_common.sh"

rc_init "$@"
rc_run
