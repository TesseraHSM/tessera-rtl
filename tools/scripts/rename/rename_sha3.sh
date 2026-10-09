#!/usr/bin/env bash
#
# rename_sha3.sh -- import + prefix the caliptra-rtl SHA-3 / Keccak engine.
#
#   ./tools/scripts/rename/rename_sha3.sh --upstream /path/to/caliptra-rtl
#
# Layout
# ------
#   caliptra-rtl                        Tessera
#   src/sha3/rtl/sha3.sv            ->  src/sha3/rtl/tessera_sha3.sv
#   src/sha3/config/sha3_ctrl.vf    ->  src/sha3/config/tessera_sha3_ctrl.vf (generated)
#
# Block-specific notes
# --------------------
# * This block is rtl/ and config/ only -- no tb/, no coverage/, no UVMF. Upstream
#   verifies SHA-3 through the KMAC block that wraps it, which is out of scope
#   here. So the import has a delivery tier and no collateral tier at all, which
#   is a useful shape to have in the demo: it shows the collateral tier is
#   genuinely optional rather than assumed.
# * rtl/ carries kmac_reg.rdl as well as sha3_reg.rdl. Both are excluded along
#   with sha3_reg_uvm.sv -- all three are register-spec input or output, not
#   source. Note the kmac .rdl sitting in sha3/rtl/ is an upstream layout quirk;
#   it is excluded by the same glob rather than by a special case.
# * The Keccak round logic is heavily macro- and generate-driven. The identifier
#   pass uses SystemVerilog boundaries rather than \b, which matters here because
#   names like sha3pad and sha3_pkg share a prefix with sha3 itself.

set -euo pipefail

BLOCK="sha3"

UPSTREAM_BLOCK_DIR="src/sha3"
BLOCK_DIR="src/sha3_shake_all_modes"

UPSTREAM_SUBTREES=(
    "src/sha3/rtl"
)

# Upstream ships no bench, coverage or stimulus for this block.
COLLATERAL_SUBTREES=()


VF_FILELIST="src/sha3/config/sha3_ctrl.vf"
VF_FILTER="/sha3/rtl/"

EXCLUDE_GLOBS=(
    "*_reg_uvm.sv"
    "*.rdl"
)

EXTRA_RENAME_IDENTS=()

# kmac is a module declared in this block, so it is prefixed -- but the sources
# also link to https://opentitan.org/book/hw/ip/kmac/doc/... , where kmac names
# a directory in OpenTitan's tree, not ours. Without this the identifier pass
# would rewrite the URL and the reverter could not undo it: it recognises
# directory names found in the staged or upstream checkouts, and no checkout
# here contains a kmac/ folder.
EXTRA_PATH_DIRS=("kmac")
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
