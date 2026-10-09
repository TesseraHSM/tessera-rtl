#!/usr/bin/env bash
#
# rename_sha256.sh -- import + prefix the caliptra-rtl SHA-256 engine.
#
#   ./tools/scripts/rename/rename_sha256.sh --upstream /path/to/caliptra-rtl
#
# Layout
# ------
#   caliptra-rtl                          Tessera
#   src/sha256/rtl/sha256.sv          ->  src/sha256/rtl/tessera_sha256.sv
#   src/sha256/coverage/...           ->  src/sha256/coverage/...
#   src/sha256/tb|stimulus            ->  same path, upstream names kept
#   src/sha256/config/sha256_ctrl.vf  ->  src/sha256/config/tessera_sha256_ctrl.vf (generated)
#
# Block-specific notes
# --------------------
# * sha256_param.sv is `include-d rather than compiled as its own unit. It is a
#   block-private header living in rtl/, so it is renamed with the rest of the
#   synthesized set and the `include that names it is rewritten to match -- that
#   is rc_fix_file_references, not the identifier pass.
# * No UVMF bench upstream: the SHA-256 environment is the directed tb/ plus
#   stimulus/, both imported as collateral.
# * sha256_reg_uvm.sv and sha256_reg.rdl are excluded as regenerated artifacts.
# * Upstream also ships sha256_random_test.vf; like every other .vf it is not
#   imported, since Tessera generates its own filelist. Only sha256_ctrl.vf is read,
#   and only to recover upstream's compile order.

set -euo pipefail

BLOCK="sha256"

UPSTREAM_BLOCK_DIR="src/sha256"
BLOCK_DIR="src/sha2_256_all_modes"

UPSTREAM_SUBTREES=(
    "src/sha256/rtl"
    "src/sha256/coverage"
)

COLLATERAL_SUBTREES=(
    "src/sha256/tb"
    "src/sha256/coverage/config"
    "src/sha256/stimulus"
)


VF_FILELIST="src/sha256/config/sha256_ctrl.vf"
VF_FILTER="/sha256/rtl/"

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
