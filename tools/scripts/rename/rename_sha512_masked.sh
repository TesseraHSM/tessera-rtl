#!/usr/bin/env bash
#
# rename_sha512_masked.sh -- import + prefix the caliptra-rtl masked SHA-512 core.
#
#   ./tools/scripts/rename/rename_sha512_masked.sh --upstream /path/to/caliptra-rtl
#
# Layout
# ------
#   caliptra-rtl                              Tessera
#   src/sha512_masked/rtl/...             ->  src/sha512_masked/rtl/tessera_...
#   src/sha512_masked/tb/...              ->  src/sha512_masked/tb/...
#   src/sha512_masked/config/..._core.vf  ->  src/sha512_masked/config/tessera_... (generated)
#
# Block-specific notes
# --------------------
# * This is the side-channel-hardened SHA-512 datapath. It is a *dependency of
#   HMAC*, not a standalone engine: hmac_core instantiates sha512_masked_core.
#   It is imported as its own block because upstream keeps it as its own
#   top-level directory, and because masking is the kind of thing you want to
#   be able to bump independently of the HMAC wrapper around it.
# * It is the only block in this import with no register file: no .rdl, no
#   _reg_uvm.sv, no coverage/ and no global `includes.
# * It reaches into the *unmasked* sha512 block for the round constants and the
#   message schedule (sha512_h_constants, sha512_k_constants, sha512_w_mem) and
#   for sha512_core. Those are declared by the sha512 import, so they are listed
#   here as cross-block identifiers: this block must rewrite its references to
#   them even though it does not own them.

set -euo pipefail

BLOCK="sha512_masked"

UPSTREAM_BLOCK_DIR="src/sha512_masked"
BLOCK_DIR="src/sha2_512_384_all_modes_masked"

UPSTREAM_SUBTREES=(
    "src/sha512_masked/rtl"
)

COLLATERAL_SUBTREES=(
    "src/sha512_masked/tb"
)


VF_FILELIST="src/sha512_masked/config/sha512_masked_core.vf"
VF_FILTER="/sha512_masked/rtl/"

EXCLUDE_GLOBS=(
    "*_reg_uvm.sv"
    "*.rdl"
)

# Declared by the sha512 import; referenced here. See the note above.
EXTRA_RENAME_IDENTS=(
    "module:sha512_core"
    "module:sha512_h_constants"
    "module:sha512_k_constants"
    "module:sha512_w_mem"
)

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
