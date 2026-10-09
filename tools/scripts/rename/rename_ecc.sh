#!/usr/bin/env bash
#
# rename_ecc.sh -- import + prefix the caliptra-rtl ECC (secp384r1) engine.
#
#   ./tools/scripts/rename/rename_ecc.sh --upstream /path/to/caliptra-rtl
#
# Layout
# ------
# The Tessera tree mirrors the caliptra-rtl hierarchy, so the correspondence
# between the two trees is 1:1:
#
#   caliptra-rtl                          Tessera
#   src/ecc/rtl/ecc_top.sv            ->  src/ecc/rtl/tessera_ecc_top.sv
#   src/ecc/coverage/ecc_top_cov_if.sv -> src/ecc/coverage/tessera_ecc_top_cov_if.sv
#   src/ecc/config/ecc_top.vf         ->  src/ecc/config/tessera_ecc_top.vf (generated)
#   src/ecc/tb/ecc_top_tb.sv          ->  src/ecc/tb/tessera_ecc_top_tb.sv
#   src/ecc/stimulus/...              ->  src/ecc/stimulus/...
#   src/ecc/uvmf_ecc/...              ->  src/ecc/uvmf_ecc/...
#
# The whole src/ecc folder is imported. rtl/ + coverage/ are the *delivery*
# (strict contract, elaborated in CI); tb/, stimulus/ and uvmf_ecc/ are
# *collateral* (same identifier map, looser contract) -- see the "Two tiers"
# section in rename_common.sh.
#
# src/ecc/formal/ is deliberately not imported: the formal properties are a
# caliptra-rtl verification asset, not part of the deliverable, and Tessera has no
# formal flow to run them in. Vendoring them would mean maintaining 42 files of
# bound properties through every upstream bump for no benefit.
#
# Block-specific notes
# --------------------
# * ECC lives in a single upstream directory (src/ecc/rtl) but instantiates
#   `hmac_drbg`, which lives in src/hmac_drbg/rtl and is its own import.
#   Ownership policy: hmac_drbg is imported exactly once, by
#   rename_hmac_drbg.sh. ECC only rewrites the *reference* so both imports link
#   against the same `<prefix>hmac_drbg` module. See EXTRA_RENAME_IDENTS.
# * Those two cross-block names are renamed under *different* policies, and
#   neither policy is stated here. hmac_param_pkg belongs to the SHA-512 HMAC
#   engine, which Tessera shelves as hmac512, so it becomes tessera_hmac512_param_pkg;
#   hmac_drbg is on the stem keep list and stays tessera_hmac_drbg. Both follow
#   from the repo-wide stem policy in rename_common.sh, which is exactly why
#   that policy is declared there and not in the owning drivers -- two drivers
#   holding two copies of the same naming decision is how they drift apart.
# * ECC guards its packages with hand-written include guards whose names do not
#   follow one pattern (CALIPTRA_ECC_DEFINES, CALIPTRA_ECC_PARAMS_PKG,
#   CALIPTRA_ECC_PM_UOP_PKG, ECC_DSA_UOP_PKG). They are discovered from the
#   sources rather than hard-coded.
# * ecc_reg_uvm.sv is a UVM register model that `includes generated covergroup
#   headers which are not part of the RTL delivery; it is excluded.
# * ecc_reg.rdl is the upstream register description. It is excluded from the
#   renamed fileset because regenerating from it would produce unprefixed RTL;
#   if Tessera ever needs to regenerate, re-run this script afterwards.
# * The coverage/ directory is imported too. It exercises a case the rtl/
#   directories do not: `bind ecc_top ecc_top_cov_if ...` -- the rename engine
#   has to rewrite the bind target as well as the interface name.
# * coverage/config/ecc_cm_hier.cfg IS imported now that the testbench comes
#   along; the hierarchy path it names (ecc_top_tb.dut) is renamed with
#   everything else.
# * src/ecc/config/ is deliberately NOT collateral. Tessera generates its own
#   filelist there, and the upstream ecc_top.vf / ecc_top_tb.vf / compile.yml
#   resolve $COMPILE_ROOT against the caliptra-rtl build environment. Copying
#   them would both collide with the generated tessera_ecc_top.vf and re-introduce
#   a dependency on an upstream build system.
# * src/ecc/tb/ecc_secp384r1.exe and the three uvmf .ucdb coverage databases are
#   build/simulation *outputs* checked into upstream. They are skipped by
#   ARTIFACT_GLOBS -- vendoring them would commit stale results.
# * ECC needs no environment configuration macros.

set -euo pipefail

BLOCK="ecc"

UPSTREAM_BLOCK_DIR="src/ecc"
BLOCK_DIR="src/ecc_ecdsa_ecdhe"

UPSTREAM_SUBTREES=(
    "src/ecc/rtl"
    "src/ecc/coverage"
)

# The rest of the src/ecc folder: imported whole, same identifier map, looser
# contract. See "Two tiers" in rename_common.sh.
COLLATERAL_SUBTREES=(
    "src/ecc/tb"
    "src/ecc/coverage/config"
    "src/ecc/stimulus"
    "src/ecc/uvmf_ecc"
)

# Every subtree above moves by swapping UPSTREAM_BLOCK_DIR for BLOCK_DIR, so
# the shelving decision is stated once at the top rather than mirrored here as
# a second copy of the same path list. Add an explicit DEST_SUBTREES entry only
# for a subtree that does not follow that swap.


VF_FILELIST="src/ecc/config/ecc_top.vf"
VF_FILTER="/ecc/rtl/"

EXCLUDE_GLOBS=(
    "*_reg_uvm.sv"   # UVM RAL model, depends on generated covergroup headers
    "*.rdl"          # SystemRDL source of the register block, see note above
)

# Cross-block dependency: declared elsewhere, renamed here so the reference
# resolves to the module that rename_hmac_drbg.sh publishes.
# Declared by other imports, referenced here. ECC instantiates hmac_drbg (owned
# by rename_hmac_drbg.sh) and imports hmac_param_pkg (owned by
# rename_hmac512.sh); this block must rewrite its references to them even though
# it does not own them. Omitting the package left Tessera's ECC importing an
# hmac_param_pkg that no longer existed under that name -- it did not fail CI
# because the generated filelist still resolved the dependency against
# ${CALIPTRA_ROOT} rather than against the Tessera copy.
EXTRA_RENAME_IDENTS=(
    "module:hmac_drbg"
    "package:hmac_param_pkg"
)

# UVMF generator inputs. These describe the verification environment -- agents,
# environments, interface ports -- and name nothing that the rename map
# touches: UVM agents and environments become SystemVerilog *classes*, which
# are scoped by their package rather than by the compilation unit. So they come
# through byte-identical, and regenerating upstream stays possible.
#
# roundtrip_check.sh asserts byte-identity for these specifically, rather than
# the naming-only equivalence it asserts everywhere else.
GENERATOR_INPUTS=(
    "src/ecc/uvmf_ecc/ECC_bench.yaml"
    "src/ecc/uvmf_ecc/ECC_environment.yaml"
    "src/ecc/uvmf_ecc/ECC_in_interface.yaml"
    "src/ecc/uvmf_ecc/ECC_out_interface.yaml"
    "src/ecc/uvmf_ecc/ECC_util_comp_ECC_predictor.yaml"
)

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
