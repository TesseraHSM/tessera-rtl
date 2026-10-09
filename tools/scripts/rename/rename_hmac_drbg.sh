#!/usr/bin/env bash
#
# rename_hmac_drbg.sh -- import + prefix the caliptra-rtl HMAC-DRBG engine.
#
#   ./tools/scripts/rename/rename_hmac_drbg.sh --upstream /path/to/caliptra-rtl
#
# Layout
# ------
# This is the one block whose Tessera directory is spelled exactly like its
# upstream one, so neither UPSTREAM_BLOCK_DIR nor DEST_SUBTREES is set and the
# identity mapping applies:
#
#   caliptra-rtl                            Tessera
#   src/hmac_drbg/rtl/hmac_drbg.sv      ->  src/hmac_drbg/rtl/tessera_hmac_drbg.sv
#   src/hmac_drbg/coverage/...          ->  src/hmac_drbg/coverage/...
#   src/hmac_drbg/tb/...                ->  src/hmac_drbg/tb/...
#   src/hmac_drbg/stimulus/...          ->  src/hmac_drbg/stimulus/...
#   src/hmac_drbg/config/hmac_drbg.vf   ->  src/hmac_drbg/config/tessera_hmac_drbg.vf (generated)
#
# The directory name is already what the block implements -- a DRBG -- so there
# is nothing for the capability-naming convention to improve on, unlike `hmac`
# (-> hmac_512_384) or `abr` (-> mldsa_mlkem_all_levels).
#
# Why this is its own import and not part of rename_hmac512.sh
# ------------------------------------------------------------
# It used to be: hmac_drbg arrived as a second pair of subtrees on the HMAC-512
# import, because both HMAC and ECC instantiate it and vendoring it twice would
# have put two copies of the same module in the Tessera netlist. Importing it
# once was right; attaching it to *another block's* import was not. A block's
# `revinfo.yml` answers "where did this come from", and src/hmac_drbg/ could
# only answer that by pointing at src/hmac_512_384/revinfo.yml -- so the record
# did not travel with the directory it described, which is the one property
# revinfo exists to have. The ownership rule is unchanged (imported exactly
# once, referenced by the others); only the owner is now hmac_drbg itself.
#
# Block-specific notes
# --------------------
# * hmac_drbg is on the repo-wide stem keep list (RC_DEFAULT_STEM_KEEP in
#   rename_common.sh), so it is prefixed but not re-stemmed: `hmac_drbg` stays
#   `hmac_drbg` rather than following `hmac` to `hmac512`. It is a DRBG shared
#   with ECC, not a SHA-512 HMAC. That policy is declared repo-wide and not
#   here because ECC and HMAC-512 both have to spell the result the same way.
# * The block instantiates `hmac_core`, which rename_hmac512.sh declares. Like
#   ECC, this import rewrites the *reference* so it resolves to the module that
#   import publishes -- under the stem policy that makes it
#   tessera_hmac512_core. See EXTRA_RENAME_IDENTS.
# * Consequently the generated filelist is not self-contained: VF_FILTER keeps
#   only this block's own line out of the upstream compile order, exactly as
#   ECC's does, and the HMAC-512 sources it instantiates come from that block's
#   filelist. Composing filelists is the integrator's job; a block's filelist
#   states that block's compile order.
# * src/hmac_drbg/formal/ is deliberately not imported, for the same reason as
#   ECC's: the properties are a caliptra-rtl verification asset and Tessera has
#   no formal flow to run them in.
# * src/hmac_drbg/config/ is not collateral. Tessera generates its own filelist
#   there, and the upstream hmac_drbg.vf / hmac_drbg_tb.vf / compile.yml resolve
#   $COMPILE_ROOT against the caliptra-rtl build environment.
# * Nothing here is excluded by glob: the block ships no UVM register model and
#   no .rdl, because it has no register interface of its own.
# * No UVMF tree, so no generator inputs; no environment configuration macros.

set -euo pipefail

BLOCK="hmac_drbg"

UPSTREAM_SUBTREES=(
    "src/hmac_drbg/rtl"
    "src/hmac_drbg/coverage"
)

# The rest of the block folder: imported whole, same identifier map, looser
# contract. See "Two tiers" in rename_common.sh.
COLLATERAL_SUBTREES=(
    "src/hmac_drbg/tb"
    "src/hmac_drbg/coverage/config"
    "src/hmac_drbg/stimulus"
)

# Tessera shelves this block where caliptra-rtl keeps it, so DEST_SUBTREES and
# COLLATERAL_DEST_SUBTREES are left at their identity defaults.

VF_FILELIST="src/hmac_drbg/config/hmac_drbg.vf"
VF_FILTER="/hmac_drbg/rtl/"

EXCLUDE_GLOBS=()

# Declared by rename_hmac512.sh, instantiated here. Omitting it would leave the
# instantiation naming a module no longer published under that name.
EXTRA_RENAME_IDENTS=(
    "module:hmac_core"
)

GENERATOR_INPUTS=()

ENV_MACRO_SPECS=()
ENV_HEADER_REPLACE=()

# Shared Tessera platform identifiers: version-pinned separately, never prefixed.
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
