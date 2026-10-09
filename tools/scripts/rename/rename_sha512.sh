#!/usr/bin/env bash
#
# rename_sha512.sh -- import + prefix the caliptra-rtl SHA-512 engine.
#
#   ./tools/scripts/rename/rename_sha512.sh --upstream /path/to/caliptra-rtl
#
# Layout
# ------
#   caliptra-rtl                          Tessera
#   src/sha512/rtl/sha512.sv          ->  src/sha512/rtl/tessera_sha512.sv
#   src/sha512/coverage/...           ->  src/sha512/coverage/...
#   src/sha512/tb|stimulus|uvmf_...   ->  same path, upstream names kept
#   src/sha512/config/sha512_ctrl.vf  ->  src/sha512/config/tessera_sha512_ctrl.vf (generated)
#
# Block-specific notes
# --------------------
# * The core is split across .v and .sv: sha512_core.v, sha512_w_mem.v and the
#   constant ROMs are Verilog-2001. The rename engine keys off file *extension*
#   for the HDL set, so .v is prefixed and rewritten exactly like .sv.
# * sha512_masked is NOT imported here. It is its own upstream directory and its
#   own Tessera block (rename_sha512_masked.sh), which in turn references the four
#   identifiers this block declares and it consumes. Keeping the ownership split
#   the same as upstream is what lets either side be bumped independently.
# * sha512_reg_uvm.sv and sha512_reg.rdl are excluded: both are regenerated from
#   the register spec, so vendoring them would commit derived state.
# * coverage/ is delivery tier but not synthesizable -- it is functional-coverage
#   bind code -- so its file names are kept and only its references are rewritten.

set -euo pipefail

BLOCK="sha512"

UPSTREAM_BLOCK_DIR="src/sha512"
BLOCK_DIR="src/sha2_512_384_all_modes"

UPSTREAM_SUBTREES=(
    "src/sha512/rtl"
    "src/sha512/coverage"
)

COLLATERAL_SUBTREES=(
    "src/sha512/tb"
    "src/sha512/coverage/config"
    "src/sha512/stimulus"
    "src/sha512/uvmf_sha512"
)


VF_FILELIST="src/sha512/config/sha512_ctrl.vf"
VF_FILTER="/sha512/rtl/"

EXCLUDE_GLOBS=(
    "*_reg_uvm.sv"
    "*.rdl"
)

EXTRA_RENAME_IDENTS=()
ENV_MACRO_SPECS=()
ENV_HEADER_REPLACE=()

# UVMF generator inputs -- must stay byte-identical so upstream regeneration
# remains possible. roundtrip_check.sh asserts that specifically.
GENERATOR_INPUTS=(
    "src/sha512/uvmf_sha512/SHA512_bench_cfg.yaml"
    "src/sha512/uvmf_sha512/SHA512_env_cfg.yaml"
    "src/sha512/uvmf_sha512/SHA512_interface_cfg.yaml"
    "src/sha512/uvmf_sha512/SHA512_util_comp.yaml"
)

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
