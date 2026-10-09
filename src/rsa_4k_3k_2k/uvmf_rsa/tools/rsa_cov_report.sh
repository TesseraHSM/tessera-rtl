#!/bin/bash
# ---------------------------------------------------------------------------
# rsa_cov_report.sh -- merge and finalize uvmf_rsa functional coverage.
#
# WHY THIS EXISTS
#   Every uvmf_rsa simulation writes a per-run coverage.vdb, but until now the
#   only thing ever read out of one was its SIZE.  `urg` is not on PATH from a
#   plain login shell, and running it with VCS_HOME set fails
#       Error-[URG-NLC] No license key ... VCSTools_Net / VT_CoverageURG
#   because the URG feature is only licensed inside the Playbook container.
#   So per-bin hit rates for rsa_cmd_cg / rsa_reject_cg / rsa_done_cg /
#   rsa_zeroize_cg were never actually read -- coverage closure was being
#   inferred from a file growing from 2475 to 2595 bytes, which is not
#   evidence of anything.
#
#   `pb fe cov merge` / `pb fe cov finalize` run INSIDE that container, so they
#   have the licence.  This wrapper is the supported way to get a readable
#   report out of the runs this bench produces.
#
# USAGE
#   RSA_SIMLAND=/path/to/simland/uvmf_rsa \
#     src/rsa_4k_3k_2k/uvmf_rsa/tools/rsa_cov_report.sh [<test_name> ...]
#
#   With no arguments it merges the most recent run of every uvmf_rsa test it
#   can find.  With arguments it merges the most recent run of each named test.
#   The merged database is written to $RSA_COV_ROOT (default:
#   <simland>/uvmf_rsa/merged_coverage).
#
#   Must be run from inside the workspace, i.e. under `enter-workspace`, so
#   that `pb` is on PATH.
#
# NOTE
#   `pb fe regress` already performs this merge as part of a suite run (see its
#   --skip-coverage-merge flag), so this script is for the ad-hoc case: a
#   handful of `pb fe sim` runs done by hand during development.
# ---------------------------------------------------------------------------
set -u

if [ -z "${RSA_SIMLAND:-}" ]; then
  echo "ERROR: set RSA_SIMLAND to the uvmf_rsa simulation output directory." >&2
  exit 1
fi
SIMLAND="$RSA_SIMLAND"
COV_ROOT="${RSA_COV_ROOT:-${SIMLAND}/merged_coverage}"
RUNS=()

if [ ! -d "$SIMLAND" ]; then
  echo "ERROR: no uvmf_rsa sim output under $SIMLAND" >&2
  echo "       set RSA_SIMLAND if your scratch area differs." >&2
  exit 1
fi

if [ "$#" -gt 0 ]; then
  TESTS=("$@")
else
  mapfile -t TESTS < <(cd "$SIMLAND" && ls -d */ 2>/dev/null | sed 's|/$||' \
                       | grep -v '^merged_coverage')
fi

FOUND=0
for t in "${TESTS[@]}"; do
  # Most recent timestamped run of this test.  Runs are named YYYYMMDD.HHMMSS,
  # so a lexical sort is a chronological sort.
  run=$(ls -d "$SIMLAND/$t"/20* 2>/dev/null | sort | tail -1)
  if [ -z "$run" ] || [ ! -d "$run/coverage.vdb" ]; then
    echo "SKIP  $t (no coverage.vdb)"
    continue
  fi
  RUNS+=("$run")
  echo "FOUND $t <- $run"
  FOUND=$((FOUND + 1))
done

if [ "$FOUND" -eq 0 ]; then
  echo "ERROR: nothing to merge." >&2
  exit 1
fi

rm -rf "$COV_ROOT"
mkdir -p "$COV_ROOT"

# --input-dir takes ONE TEST DIRECTORY, not a directory of databases:
# Plugins/CoverageTypes/VCS.py:get_coverage_input() looks for exactly
# "<input-dir>/coverage.vdb" and returns [] otherwise -- which is reported as
# the easily-missed INFO line "No input file found for VCS coverage in test
# directory: ..." and a successful exit code.  So merge one run at a time and
# let --cov-root accumulate.
for run in "${RUNS[@]}"; do
  echo "MERGE $run"
  pb fe cov merge --cov-root "$COV_ROOT" --input-dir "$run" || exit $?
done

pb fe cov finalize --coverage-root "$COV_ROOT" || exit $?

echo
echo "Merged coverage database: $COV_ROOT"
echo "Open with:   verdi -cov -covdir $COV_ROOT"
