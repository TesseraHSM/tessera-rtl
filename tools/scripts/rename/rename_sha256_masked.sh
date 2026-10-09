#!/usr/bin/env bash
#
# rename_sha256_masked.sh -- import + prefix the caliptra-rtl masked SHA-256 core.
#
#   ./tools/scripts/rename/rename_sha256_masked.sh --upstream /path/to/caliptra-rtl \
#       --branch future
#
# Layout
# ------
#   caliptra-rtl                              Tessera
#   src/sha256_masked/rtl/...             ->  src/sha256_masked/rtl/tessera_...
#   src/sha256_masked/tb/...              ->  src/sha256_masked/tb/...
#   src/sha256_masked/config/..._core.vf  ->  src/sha256_masked/config/tessera_... (generated)
#
# Block-specific notes
# --------------------
# * This block does not exist on `main`. Like hmac256 it lives on caliptra-rtl's
#   `future` branch, so the import must be run with `--branch future` -- the
#   branch is *declared*, not read from the checkout, because CI re-imports from
#   a detached HEAD. The recorded commit pins the content; the branch tells you
#   which changelog to read when pulling an update.
#
# * This is the side-channel-hardened SHA-256 datapath, the 256-bit counterpart
#   of sha512_masked. It is a *dependency of HMAC-256*, not a standalone engine:
#   hmac256_core instantiates sha256_masked_core. It is imported as its own
#   block because upstream keeps it as its own top-level directory, and because
#   masking is the kind of thing you want to be able to bump independently of
#   the HMAC wrapper around it.
#
# * Like sha512_masked it has no register file: no .rdl, no _reg_uvm.sv, no
#   coverage/ and no global `includes. EXCLUDE_GLOBS is kept for symmetry with
#   the other blocks rather than because anything matches today.
#
# * It reaches into the *unmasked* sha256 block for the round constants
#   (sha256_k_constants, instantiated in sha256_masked_core.sv). That module is
#   declared by the sha256 import, so it is listed here as a cross-block
#   identifier: this block must rewrite its reference to it even though it does
#   not own it. Unlike sha512_masked it names nothing else from its unmasked
#   sibling -- no sha256_core, no sha256_w_mem -- because the masked datapath
#   carries its own schedule in sha256_masked_w_mem. Verified by grepping rtl/,
#   not inferred from the .vf, which lists the whole sha256 tree purely as
#   compile order.
#
# * Importing this block closes the gap called out in rename_hmac256.sh: with
#   sha256_masked_core now declared as tessera_sha256_masked_core, hmac256 carries
#   EXTRA_RENAME_IDENTS=("module:sha256_masked_core") so its instantiation
#   follows the declaration. Keep the two in step.

set -euo pipefail

BLOCK="sha256_masked"

UPSTREAM_BLOCK_DIR="src/sha256_masked"
BLOCK_DIR="src/sha2_256_all_modes_masked"

UPSTREAM_SUBTREES=(
    "src/sha256_masked/rtl"
)

COLLATERAL_SUBTREES=(
    "src/sha256_masked/tb"
)


VF_FILELIST="src/sha256_masked/config/sha256_masked_core.vf"
VF_FILTER="/sha256_masked/rtl/"

EXCLUDE_GLOBS=(
    "*_reg_uvm.sv"
    "*.rdl"
)

# Declared by the sha256 import; referenced here. See the note above.
EXTRA_RENAME_IDENTS=(
    "module:sha256_k_constants"
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
