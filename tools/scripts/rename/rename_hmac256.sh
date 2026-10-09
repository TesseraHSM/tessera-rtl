#!/usr/bin/env bash
#
# rename_hmac256.sh -- import + prefix the caliptra-rtl HMAC-SHA-256 engine.
#
#   ./tools/scripts/rename/rename_hmac256.sh --upstream /path/to/caliptra-rtl \
#       --branch future
#
# Layout
# ------
#   caliptra-rtl                            Tessera
#   src/hmac256/rtl/hmac256.sv          ->  src/hmac256/rtl/tessera_hmac256.sv
#   src/hmac256/coverage/...            ->  src/hmac256/coverage/...
#   src/hmac256/tb|stimulus|uvmf_hmac256 -> same path, upstream names kept
#   src/hmac256/config/hmac256_ctrl.vf  ->  src/hmac256/config/tessera_hmac256_ctrl.vf
#
# Block-specific notes
# --------------------
# * This block does not exist on `main`. It lives on caliptra-rtl's `future`
#   branch, so the import must be run with `--branch future` -- the branch is
#   *declared*, not read from the checkout, because CI re-imports from a
#   detached HEAD. The recorded commit is what pins the content; the branch is
#   what tells you which changelog to read when pulling an update.
#
# * hmac256 instantiates `sha256_masked_core`, which lives in src/sha256_masked/
#   -- now its own Tessera block (rename_sha256_masked.sh), so the identifier is
#   declared as tessera_sha256_masked_core and this import has to rewrite its
#   reference to match. That is what the EXTRA_RENAME_IDENTS entry below does.
#   Leaving it out is the failure mode worth naming: hmac256 would instantiate
#   the upstream module while Tessera declares the prefixed one, and that is
#   invisible to the generated filelist, which resolves cross-block names
#   against ${CALIPTRA_ROOT} rather than against the vendored tree.
#   sha256_masked is on `future` too, so the two blocks move together.
#
# * hmac256 also sits on top of src/sha256/, which Tessera *does* vendor -- but it
#   names no identifier from it (only sha256_masked_core), so there is nothing
#   to add to the map. Verified by grepping the rtl/ sources rather than
#   assumed from the .vf, which lists sha256 sources purely as compile order.
#
# * Unlike hmac (512), hmac256 reads no environment-supplied configuration
#   macro: hmac256_param_pkg hard-codes its widths rather than deriving them
#   from CLP_CSR_* in caliptra_macros.svh. ENV_MACRO_SPECS is empty for that
#   reason, not by oversight.
#
# * hmac256_reg_uvm.sv and hmac256_reg.rdl are excluded as regenerated
#   artifacts; hmac256_reg_covergroups.svh / _reg_sample.svh are `include-d by
#   the register block and are renamed with it.

set -euo pipefail

BLOCK="hmac256"

UPSTREAM_BLOCK_DIR="src/hmac256"
BLOCK_DIR="src/hmac_256"

UPSTREAM_SUBTREES=(
    "src/hmac256/rtl"
    "src/hmac256/coverage"
)

COLLATERAL_SUBTREES=(
    "src/hmac256/tb"
    "src/hmac256/coverage/config"
    "src/hmac256/stimulus"
    "src/hmac256/uvmf_hmac256"
)


VF_FILELIST="src/hmac256/config/hmac256_ctrl.vf"
VF_FILTER="/hmac256/rtl/"

EXCLUDE_GLOBS=(
    "*_reg_uvm.sv"
    "*.rdl"
)

# Declared by rename_sha256_masked.sh, instantiated by hmac256_core.
EXTRA_RENAME_IDENTS=(
    "module:sha256_masked_core"
)

ENV_MACRO_SPECS=()
ENV_HEADER_REPLACE=()

# The UVMF generator inputs: these describe UVM *classes*, not design names, so
# they must come across byte-identical or regenerating the bench would no longer
# reproduce the vendored output. roundtrip_check.sh compares them without
# stripping the prefix, which is what makes that claim checkable.
GENERATOR_INPUTS=(
    "src/hmac256/uvmf_hmac256/HMAC256_bench.yaml"
    "src/hmac256/uvmf_hmac256/HMAC256_environment.yaml"
    "src/hmac256/uvmf_hmac256/HMAC256_global.yaml"
    "src/hmac256/uvmf_hmac256/HMAC256_interfaces.yaml"
    "src/hmac256/uvmf_hmac256/HMAC256_util_comp_predictor.yaml"
    "src/hmac256/uvmf_hmac256/HMAC256_util_comp_scoreboard.yaml"
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
