#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# check_filelists.sh -- every path a UVMF filelist names must exist.
#
# The rename touches generated verification IP in two ways that can disagree
# with each other:
#
#   * the identifier pass rewrites a package name wherever it appears -- and in
#     a UVMF .f list the package name appears *inside a path*, because UVMF
#     names a VIP directory after the package it holds:
#
#         $UVMF_VIP_LIBRARY_HOME/interface_packages/ECC_in_pkg/ECC_in_pkg.sv
#
#   * the file/directory pass moves the files those paths point at.
#
# If those two ever drift apart the filelist dangles, and nothing else in the
# verification suite notices: slang only elaborates the delivery tier, and the
# round-trip is happy because a consistently-wrong path still strips back to
# the upstream one. This check is what closes that gap. It is the enforcement
# behind the README's claim that the UVMF collateral is reference-consistent.
#
# Resolution rules, taken from the UVMF run scripts:
#
#     $UVMF_VIP_LIBRARY_HOME  -> <template_output>/verification_ip
#     $UVMF_PROJECT_DIR       -> <template_output>/project_benches/<BENCH>
#     ${UVM_HOME}, $UVMF_HOME -> external, not vendored, skipped
#     uvmf_base_pkg/...       -> the UVMF library itself, not vendored, skipped
#     relative paths          -> relative to the filelist's own directory
#
# Usage: check_filelists.sh [--dest <repo-root>]
# Exit 0 if every vendored path resolves, 1 otherwise.
# ---------------------------------------------------------------------------
set -euo pipefail

DEST="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
while [ $# -gt 0 ]; do
    case "$1" in
        --dest) DEST="$(cd "$2" && pwd)"; shift 2 ;;
        -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
        *) echo "check_filelists.sh: unknown argument '$1'" >&2; exit 2 ;;
    esac
done

[ -d "$DEST/src" ] || { echo "check_filelists.sh: no src/ under $DEST" >&2; exit 2; }

rc=0 nlists=0 nrefs=0 nskip=0

while IFS= read -r fl; do
    nlists=$((nlists + 1))
    fldir="$(dirname "$fl")"

    # walk up to the uvmf_template_output root this filelist lives under
    root="$fldir" up=""
    while [ "$root" != "/" ] && [ "$root" != "$up" ] \
          && [ "$(basename "$root")" != "uvmf_template_output" ]; do
        up="$root"; root="$(dirname "$root")"
    done
    if [ "$(basename "$root")" != "uvmf_template_output" ]; then
        vip=""; proj=""
    else
        vip="$root/verification_ip"
        # <root>/project_benches/<BENCH> -- there is exactly one per block
        proj="$(find "$root/project_benches" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -1)"
    fi

    while IFS= read -r line; do
        # strip comments and compiler switches; keep bare paths only
        line="${line%%//*}"
        line="$(printf '%s' "$line" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
        # a handful of vendored ".f" files are actually shell run scripts
        # (QVIP ships qrun_32.f / qrun_64.f). They use backslash line
        # continuations and mix switches, assignments and paths on one line.
        line="${line%\\}"
        line="$(printf '%s' "$line" | sed -E 's/[[:space:]]+$//')"
        [ -n "$line" ] || continue
        case "$line" in
            '+'*|'-'*|'#'*) continue ;;
        esac
        # a filelist entry is a single token; anything with whitespace left in
        # it is a command line, not a path
        case "$line" in
            *[[:space:]]*) nskip=$((nskip + 1)); continue ;;
        esac

        # external dependencies we deliberately do not vendor
        case "$line" in
            *'${UVM_HOME}'*|*'$UVM_HOME'*|*'$UVMF_HOME'*|*uvmf_base_pkg*)
                nskip=$((nskip + 1)); continue ;;
        esac

        p="$line"
        case "$p" in
            '$UVMF_VIP_LIBRARY_HOME'/*) [ -n "$vip" ]  && p="$vip/${p#'$UVMF_VIP_LIBRARY_HOME'/}" ;;
            '$UVMF_PROJECT_DIR'/*)      [ -n "$proj" ] && p="$proj/${p#'$UVMF_PROJECT_DIR'/}" ;;
            '$'*|'${'*) nskip=$((nskip + 1)); continue ;;   # some other environment root
            /*) : ;;
            *) p="$fldir/$p" ;;
        esac

        nrefs=$((nrefs + 1))
        if [ ! -e "$p" ]; then
            printf '  FAIL  %s\n          names %s\n          which resolves to %s -- missing\n' \
                   "${fl#"$DEST"/}" "$line" "${p#"$DEST"/}"
            rc=1
        fi
    done < <(cat "$fl"; echo)   # trailing newline: UVMF emits filelists without one
done < <(find "$DEST/src" \( -name '*.f' -o -name '*.F' \) -type f | sort)

if [ "$rc" -eq 0 ]; then
    printf '  ok    %d vendored path(s) in %d UVMF filelist(s) all resolve (%d external ref(s) skipped)\n' \
           "$nrefs" "$nlists" "$nskip"
    echo "check_filelists: all filelist references resolve"
else
    echo "check_filelists: dangling filelist reference(s) -- the rename moved a file the filelist still names" >&2
fi
exit "$rc"
