#!/usr/bin/env bash
#
# rename_aes.sh -- import + prefix the caliptra-rtl AES engine.
#
#   ./tools/scripts/rename/rename_aes.sh --upstream /path/to/caliptra-rtl
#
# Layout
# ------
#   caliptra-rtl                   Tessera
#   src/aes/rtl/aes.sv         ->  src/aes/rtl/tessera_aes.sv
#   src/aes/coverage/...       ->  src/aes/coverage/...
#   src/aes/config/aes.vf      ->  src/aes/config/tessera_aes.vf (generated)
#
# Block-specific notes
# --------------------
# * Much the largest block in this import: 45 RTL files declaring 51 modules and
#   packages, because the masked AES datapath is decomposed into DOM-protected
#   S-boxes, per-round key expansion and a full control FSM.
# * It is an OpenTitan-derived core wrapped for Caliptra, so it carries the
#   widest set of `includes of any block here: caliptra_prim_assert.sv,
#   caliptra_prim_module_name_macros.svh, caliptra_reg_field_defines.svh and
#   kv_macros.svh. None of those are *configuration* macros -- they do not change
#   what the block synthesizes to -- so they are resolved via +incdir in the
#   generated filelist rather than captured into a block-private header the way
#   HMAC's CLP_CSR_HMAC_KEY_DWORDS is. See "Known gaps" in the README.
# * data/ and lint/ are not imported. data/aes.rdl is register-spec input, and
#   lint/aes.vlt is a Verilator waiver file naming tool-specific paths -- both
#   are build-system inputs, treated the same way as config/ and the hmac
#   rtl_lint waiver.
# * aes_clp_reg_uvm.sv and aes_clp_reg.rdl are excluded as regenerated artifacts.
# * Upstream splits the filelist in two: aes_pkg.vf (packages, compiled first)
#   and aes.vf. Only aes.vf is read for compile order; Tessera emits one filelist.

set -euo pipefail

BLOCK="aes"

UPSTREAM_BLOCK_DIR="src/aes"
BLOCK_DIR="src/aes_all_modes"

UPSTREAM_SUBTREES=(
    "src/aes/rtl"
    "src/aes/coverage"
)

COLLATERAL_SUBTREES=()


VF_FILELIST="src/aes/config/aes.vf"
VF_FILTER="/aes/rtl/"

EXCLUDE_GLOBS=(
    "*_reg_uvm.sv"
    "*.rdl"
)

EXTRA_RENAME_IDENTS=()
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
