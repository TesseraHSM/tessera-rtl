#!/usr/bin/env bash
#
# roundtrip_check.sh -- prove the rename is a *pure token substitution*.
#
#   ./tools/scripts/rename/roundtrip_check.sh [--block ecc] --upstream <dir>
#
# For every imported file this strips the Tessera prefix back off and diffs the
# result against the exact upstream blob recorded in the block's revinfo.yml.
# A clean run means the vendored RTL differs from caliptra-rtl by nothing but
# names -- no accidental logic edits, no dropped lines, no mangled strings.
#
# The set of files proved is the *committed tree*, enumerated over the subtrees
# the block declared, rather than a recorded file list. That way every committed
# file has to justify itself by mapping back to a real upstream blob; a file
# added locally cannot escape the proof just by not being on a list. Only the
# files the import declares it generated (artifacts.generated -- the compile
# -order filelist and the captured environment-macro header) are exempt, and
# those are held to bit-identical regeneration by CI instead.
#
# The complementary direction -- an upstream file that was never imported --
# is covered by the re-import job, which regenerates every block and fails on
# any file that comes back changed or uncommitted.
#
# The only differences tolerated are `include redirections, which the import
# performs on purpose when it captures environment configuration macros into a
# block-private header.
#
# "Stripping the prefix" is not quite the whole inverse. A block may also carry
# a *stem* rewrite (hmac_core -> hmac512_core, HMAC_PARAM_PKG -> HMAC512_PARAM_PKG),
# which this has to undo as well or every file in that block reads as a difference.
# The policy is read back out of the block's own revinfo.yml rather than
# hard-coded, so the check stays an inverse of whatever the import declared.

set -euo pipefail

# shellcheck source=revinfo_lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/revinfo_lib.sh"

DEST="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
UPSTREAM=""
BLOCK=""

while [ $# -gt 0 ]; do
    case "$1" in
        --upstream) UPSTREAM="${2:?}"; shift 2 ;;
        --block)    BLOCK="${2:?}";    shift 2 ;;
        --dest)     DEST="${2:?}";     shift 2 ;;
        --help|-h)  sed -n '2,14p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

# the work-tree guard below compares DEST against `git rev-parse --show-toplevel`,
# which is always absolute; canonicalise so that --dest . matches rather than
# tripping the guard.
DEST="$(cd "$DEST" 2>/dev/null && pwd)" \
    || { echo "--dest is not a directory" >&2; exit 2; }

if [ -z "$UPSTREAM" ]; then
    UPSTREAM="$DEST/.upstream-cache/caliptra-rtl"
fi
# a linked worktree has .git as a file, and a worktree is how you check out a
# second branch of the same clone -- which blocks that only exist on `future`
# need.
git -C "$UPSTREAM" rev-parse --git-dir >/dev/null 2>&1 \
    || { echo "need --upstream <caliptra-rtl checkout>" >&2; exit 2; }

blocks=()
if [ -n "$BLOCK" ]; then
    blocks=("$BLOCK")
else
    while read -r b _; do blocks+=("$b"); done < <(ri_find "$DEST")
fi

rc=0
# an empty block list must be loud: a wrong --dest, a relocated src/, or a
# directory rename would otherwise iterate zero times and report success
# without having proved anything. The per-block work-tree guard below cannot
# cover this, because it only runs once a block has already been found.
if [ "${#blocks[@]}" -eq 0 ]; then
    echo "roundtrip_check: no blocks found under $DEST/src -- nothing to prove" >&2
    exit 1
fi

for b in "${blocks[@]}"; do
    revinfo="$(ri_path "$DEST" "$b" || true)"
    [ -f "$revinfo" ] || { echo "missing $revinfo" >&2; rc=1; continue; }

    sha="$(sed -nE 's/^[[:space:]]*commit:[[:space:]]*"([0-9a-f]+)".*/\1/p' "$revinfo" | head -1)"
    prefix="$(sed -nE 's/^prefix:[[:space:]]*"(.*)"$/\1/p' "$revinfo" | head -1)"
    macro_prefix="$(printf '%s' "$prefix" | tr '[:lower:]' '[:upper:]')"

    # policy.stem_renames / policy.stem_keep, as recorded at import time
    stem_renames=()
    while IFS= read -r tok; do [ -n "$tok" ] && stem_renames+=("$tok"); done \
        < <(sed -nE '/^[[:space:]]*stem_renames:/,/^[[:space:]]*stem_keep:/ s/^[[:space:]]*-[[:space:]]*"([^"]+)".*/\1/p' "$revinfo")

    # Undo the stem on one name: hmac512_core -> hmac_core, hmac512.sv -> hmac.sv.
    # Only an exact match or a "<to>_" / "<to>." lead is inverted, which is the
    # same shape rc_stem applied going the other way.
    unstem() {
        local n="$1" r from to
        for r in "${stem_renames[@]}"; do
            from="${r%%=*}"; to="${r#*=}"
            case "$n" in
                "$to"|"$to"_*|"$to".*) printf '%s%s' "$from" "${n#"$to"}"; return 0 ;;
            esac
        done
        printf '%s' "$n"
    }

    stem_keep=()
    while IFS= read -r tok; do [ -n "$tok" ] && stem_keep+=("$tok"); done \
        < <(sed -nE '/^[[:space:]]*stem_keep:/,/^[[:space:]]*synth_subtrees:/ s/^[[:space:]]*-[[:space:]]*"([^"]+)".*/\1/p' "$revinfo")

    # Forward direction, for the "guess the renamed path" fallbacks below.
    restem() {
        local n="$1" r from to
        for r in "${stem_keep[@]}"; do
            case "$n" in "$r"|"$r"_*|"$r".*) printf '%s' "$n"; return 0 ;; esac
        done
        for r in "${stem_renames[@]}"; do
            from="${r%%=*}"; to="${r#*=}"
            case "$n" in
                "$from"|"$from"_*|"$from".*) printf '%s%s' "$to" "${n#"$from"}"; return 0 ;;
            esac
        done
        printf '%s' "$n"
    }

    # The full inverse of the import, applied to file *content*: undo the stem,
    # then drop the prefix. The stem half has to be *anchored*, because unlike
    # "tessera_" -- which can only ever be something this toolchain put there --
    # the string "hmac512" occurs in upstream of its own accord (hmac512_op in
    # the UVMF enums). Blindly inverting it would rewrite upstream's own names
    # and report a difference that is not there.
    #
    # The rename only ever produces the stem in two shapes, so only those two
    # are inverted:
    #   1. directly behind the prefix   tessera_hmac512_core -> hmac_core
    #                                   TESSERA_HMAC512_PARAM_PKG -> HMAC_PARAM_PKG
    #   2. as a whole path component    tessera_hmac512 -> hmac
    #      (rc_fix_path_components strips the prefix back off these)
    # Anything else -- hmac512_op, hmac512 in a comment upstream wrote -- is
    # left exactly as found. Token boundaries make this perl rather than sed.
    uninvert() {
        perl -e '
            my ($prefix, $mprefix, $nstem, @rest) = @ARGV;
            my @stems = splice(@rest, 0, $nstem);
            open(my $in, "<", $rest[0]) or die "$rest[0]: $!";
            local $/; my $t = <$in>; close $in;
            for my $s (@stems) {
                my ($from, $to) = split /=/, $s, 2;
                next unless defined $to and length $to;
                my ($ufrom, $uto) = (uc $from, uc $to);
                $t =~ s/\Q$prefix$to\E(?![A-Za-z0-9])/$from/g;
                $t =~ s/\Q$mprefix$uto\E(?![A-Za-z0-9])/$ufrom/g;
                $t =~ s{(?<=/)\Q$to\E(?![A-Za-z0-9_])}{$from}g;
            }
            $t =~ s/\Q$prefix\E//g;
            $t =~ s/\Q$mprefix\E//g;
            print $t;
        ' "$prefix" "$macro_prefix" "${#stem_renames[@]}" ${stem_renames[@]+"${stem_renames[@]}"} "$1"
    }

    git -C "$UPSTREAM" cat-file -e "$sha^{commit}" 2>/dev/null || {
        echo "upstream checkout does not contain $sha (fetch it first)" >&2; rc=1; continue; }

    # A block may vendor from more than one repository. ABR takes its coverage
    # bind from caliptra-rtl and all 153 RTL files from the adams-bridge
    # submodule, which has its own history -- so "what did this look like
    # upstream" has to be asked of the right repo at the right sha.
    sub_paths=(); sub_shas=()
    while IFS='|' read -r sp sbr ssha; do
        [ -n "${ssha:-}" ] || continue
        sub_paths+=("$sp"); sub_shas+=("$ssha")
        # A submodule may be pinned ahead of the superproject gitlink (see
        # SUBMODULE_COMMITS), in which case `git submodule update` leaves the
        # recorded commit unfetched. The branch is recorded for exactly this:
        # it is what makes the pinned commit reachable.
        git -C "$UPSTREAM/$sp" cat-file -e "$ssha^{commit}" 2>/dev/null \
            || { [ -z "${sbr:-}" ] || git -C "$UPSTREAM/$sp" fetch --quiet origin \
                     "+refs/heads/$sbr:refs/remotes/origin/$sbr" 2>/dev/null || true; }
        git -C "$UPSTREAM/$sp" cat-file -e "$ssha^{commit}" 2>/dev/null || {
            echo "submodule $sp does not contain $ssha (git submodule update --init?)" >&2
            rc=1; }
    done < <(awk '
        /^  submodules:/ { in_s=1; next }
        /^  subtrees:/   { in_s=0 }
        in_s && /^[[:space:]]*-[[:space:]]*path:/ {
            if (p != "") print p "|" b "|" c; b=""; c=""
            p=$0; sub(/.*path:[[:space:]]*"/,"",p); sub(/".*/,"",p); next }
        in_s && /^[[:space:]]*branch:/ { b=$0; sub(/.*branch:[[:space:]]*"/,"",b); sub(/".*/,"",b); next }
        in_s && /^[[:space:]]*commit:/ { c=$0; sub(/.*commit:[[:space:]]*"/,"",c); sub(/".*/,"",c); next }
        END { if (p != "") print p "|" b "|" c }
    ' "$revinfo")

    # repo + sha to ask about an upstream path
    upstream_repo_for() {
        local up="$1" i
        for i in "${!sub_paths[@]}"; do
            case "$up" in "${sub_paths[$i]}"/*)
                printf '%s\t%s\t%s\n' "$UPSTREAM/${sub_paths[$i]}" "${sub_shas[$i]}" \
                       "${up#"${sub_paths[$i]}"/}"
                return 0 ;;
            esac
        done
        printf '%s\t%s\t%s\n' "$UPSTREAM" "$sha" "$up"
    }

    printf '\n== %s (upstream %s, prefix %s) ==\n' "$b" "${sha:0:12}" "$prefix"

    # upstream subtree -> Tessera subtree, as recorded at import time
    declare -A dirmap=()
    while IFS='|' read -r up ar; do
        [ -n "${ar:-}" ] || continue
        dirmap["$up"]="$ar"
    done < <(sed -nE 's/^[[:space:]]*-[[:space:]]*\{[[:space:]]*upstream:[[:space:]]*"([^"]+)",[[:space:]]*tessera:[[:space:]]*"([^"]+)".*/\1|\2/p' "$revinfo")

    # dirmap keys whole directories, which is enough for the delivery tier
    # (staged one level deep) but not for collateral, which is recursive. Keep
    # the roots separately and resolve by longest matching prefix.
    roots_up=(); roots_tessera=()
    for up in "${!dirmap[@]}"; do
        roots_up+=("$up"); roots_tessera+=("${dirmap[$up]}")
    done
    remap_path() {
        local up="$1" i best=-1 blen=0
        for i in "${!roots_up[@]}"; do
            case "$up" in "${roots_up[$i]}"/*)
                [ "${#roots_up[$i]}" -gt "$blen" ] && { blen="${#roots_up[$i]}"; best="$i"; } ;;
            esac
        done
        if [ "$best" -ge 0 ]; then
            printf '%s%s\n' "${roots_tessera[$best]}" "${up#"${roots_up[$best]}"}"
        else
            printf '%s\n' "$up"
        fi
    }

    # Resolving upstream path -> Tessera path: both file names *and* directory
    # names may carry the prefix (UVMF names a directory after the package it
    # holds). Rather than re-deriving the rule, strip the prefix out of every
    # committed path and index by the result -- that is the upstream path.
    #
    # The stem is the second half of the inverse, and it has to be undone
    # *below* the Tessera subtree root, never on the root itself: the key is
    # compared against remap_path's output, which already speaks Tessera
    # directories. For src/hmac_512_384/rtl/tessera_hmac512_core.sv the key wanted is
    # src/hmac_512_384/rtl/hmac_core.sv -- Tessera directory, upstream file name.
    tessera_key() {
        local rp="${1//${prefix}/}" i best=-1 blen=0 root rest comp out
        for i in "${!roots_tessera[@]}"; do
            case "$rp" in "${roots_tessera[$i]}"/*)
                [ "${#roots_tessera[$i]}" -gt "$blen" ] && { blen="${#roots_tessera[$i]}"; best="$i"; } ;;
            esac
        done
        if [ "$best" -lt 0 ]; then printf '%s' "$rp"; return 0; fi
        root="${roots_tessera[$best]}"; rest="${rp#"$root"/}"; out="$root"
        local -a comps=()
        IFS='/' read -r -a comps <<< "$rest"
        for comp in "${comps[@]}"; do out="$out/$(unstem "$comp")"; done
        printf '%s' "$out"
    }

    # local Tessera path -> upstream path. tessera_key undoes the prefix and the
    # stem but leaves the path in Tessera directories; this then undoes the
    # subtree relocation, which is exactly remap_path run backwards (longest
    # matching Tessera root wins, same as the forward direction).
    unmap_path() {
        local k i best=-1 blen=0
        k="$(tessera_key "$1")"
        for i in "${!roots_tessera[@]}"; do
            case "$k" in "${roots_tessera[$i]}"/*)
                [ "${#roots_tessera[$i]}" -gt "$blen" ] && { blen="${#roots_tessera[$i]}"; best="$i"; } ;;
            esac
        done
        if [ "$best" -ge 0 ]; then
            printf '%s%s\n' "${roots_up[$best]}" "${k#"${roots_tessera[$best]}"}"
        else
            printf '%s\n' "$k"
        fi
    }

    # Files the import declared it produced itself (the compile-order filelist
    # and, where a block needed one, the captured environment-macro header).
    # They have no upstream blob to diff against; the re-import job is what
    # holds them to their contract.
    # Reset explicitly: these are rebuilt per block, and a stale entry carried
    # over from the previous block would exempt the wrong file.
    unset generated seen_up
    declare -A generated=()
    declare -A seen_up=()

    while IFS= read -r g; do
        [ -n "$g" ] || continue
        generated["$g"]=1
    done < <(sed -nE '/^  generated:/,/^$/ s/^[[:space:]]*-[[:space:]]*(.+)$/\1/p' "$revinfo")

    # The set of files to prove is the committed tree itself, enumerated over
    # the subtrees the block declared. Driving from the tree rather than from a
    # recorded file list means every committed file has to justify itself
    # against upstream: a file added locally can no longer go unexamined
    # because it simply was not on the list.
    blockdirs=()
    while IFS= read -r d; do [ -n "$d" ] && blockdirs+=("$d"); done < <(
        sed -nE '/^  source_dirs:/,/^  (collateral_dirs|filelist):/ s/^[[:space:]]*-[[:space:]]*(.+)$/\1/p' "$revinfo"
        sed -nE '/^  collateral_dirs:/,/^  filelist:/ s/^[[:space:]]*-[[:space:]]*(.+)$/\1/p' "$revinfo")
    if [ "${#blockdirs[@]}" -eq 0 ]; then
        echo "  FAIL  revinfo.yml declares no source_dirs"; rc=1; continue
    fi
    # Enumerating from git is what makes this check meaningful, so refuse to
    # degrade into "proved nothing, exited 0" if git cannot answer: a wrong cwd,
    # an unpacked tarball, or a renamed block directory must all be loud.
    top="$(git -C "$DEST" rev-parse --show-toplevel 2>/dev/null || true)"
    if [ -z "$top" ] || [ "$top" != "$DEST" ]; then
        echo "  FAIL  $DEST is not the root of a git work tree; cannot enumerate the block" >&2
        rc=1; continue
    fi
    emptydir=0
    for d in "${blockdirs[@]}"; do
        [ -n "$(git -C "$DEST" ls-files -- "$d")" ] && continue
        printf '  FAIL  declared subtree %s holds no tracked files\n' "$d"; rc=1; emptydir=1
    done
    [ "$emptydir" -eq 0 ] || continue

    checked=0
    binchecked=0
    skipped=0

    while IFS= read -r rel; do
        [ -n "${rel:-}" ] || continue
        if [ -n "${generated[$rel]:-}" ]; then skipped=$((skipped + 1)); continue; fi

        renamed="$DEST/$rel"
        [ -f "$renamed" ] || { printf '  FAIL  tracked but absent from the work tree: %s\n' "$rel"; rc=1; continue; }

        upath="$(unmap_path "$rel")"
        # Two local files collapsing onto one upstream path would mean the
        # inverse mapping is wrong, and one of the two would be proved against
        # the other's source. Refuse rather than report a false pass.
        if [ -n "${seen_up[$upath]:-}" ]; then
            printf '  FAIL  %s and %s both map to upstream %s\n' "${seen_up[$upath]}" "$rel" "$upath"
            rc=1; continue
        fi
        seen_up["$upath"]="$rel"

        IFS=$'\t' read -r urepo usha urel < <(upstream_repo_for "$upath")
        if ! git -C "$urepo" cat-file -e "$usha:$urel" 2>/dev/null; then
            printf '  FAIL  %s has no upstream counterpart (derived %s)\n' "$rel" "$upath"
            printf '        not vendored and not declared under artifacts.generated\n'
            rc=1; continue
        fi

        if ! grep -Iq . "$renamed" 2>/dev/null; then
            # binary collateral: must be carried through byte-for-byte
            if git -C "$urepo" show "$usha:$urel" | cmp -s - "$renamed"; then
                binchecked=$((binchecked + 1))
            else
                printf '  FAIL  %s binary content changed\n' "$upath"
                rc=1
            fi
            continue
        fi

        if diffout="$(diff <(uninvert "$renamed") \
                          <(git -C "$urepo" show "$usha:$urel"))"; then
            checked=$((checked + 1))
            continue
        fi

        # tolerate deliberate `include redirections only
        if [ -z "$(printf '%s\n' "$diffout" | grep -E '^[<>]' | grep -vE '`include')" ]; then
            printf '  ok    %s (include redirected on purpose)\n' "$upath"
            checked=$((checked + 1))
        else
            printf '  FAIL  %s differs beyond renaming:\n' "$upath"
            printf '%s\n' "$diffout" | sed 's/^/        /'
            rc=1
        fi
    done < <(git -C "$DEST" ls-files -- "${blockdirs[@]}")

    # Code-generator inputs are held to a *stronger* contract than everything
    # else: byte-identical, not merely naming-equivalent. The loop above strips
    # the prefix before diffing, so a yaml that had wrongly been prefixed would
    # strip straight back to the upstream text and pass unnoticed -- and the
    # next regeneration would then emit names that disagree with what is
    # committed. Compare these against upstream directly.
    local_gi=0
    while IFS= read -r gi; do
        [ -n "$gi" ] || continue
        # declared by upstream path; committed at the Tessera path for that subtree
        gi_tessera="$(remap_path "$gi")"
        if [ ! -f "$DEST/$gi_tessera" ]; then
            printf '  FAIL  generator input %s declared but not imported (looked for %s)\n' "$gi" "$gi_tessera"
            rc=1; continue
        fi
        if git -C "$UPSTREAM" show "$sha:$gi" 2>/dev/null | cmp -s - "$DEST/$gi_tessera"; then
            local_gi=$((local_gi + 1))
        else
            printf '  FAIL  generator input %s is not byte-identical to upstream\n' "$gi"
            printf '        regeneration would diverge from what is committed\n'
            rc=1
        fi
    done < <(sed -nE '/^[[:space:]]*generator_inputs:/,/^[[:space:]]*keep_list:/ s/^[[:space:]]*-[[:space:]]*"([^"]+)".*/\1/p' "$revinfo")
    [ "$local_gi" -eq 0 ] || printf '  ok    %d generator input(s) byte-identical to upstream\n' "$local_gi"

    [ "$binchecked" -eq 0 ] || printf '  ok    %d binary file(s) carried byte-for-byte\n' "$binchecked"
    [ "$skipped" -eq 0 ] || printf '  --    %d generated file(s) skipped (no upstream counterpart)\n' "$skipped"
    printf '  -- %d file(s) round-tripped\n' "$checked"
    [ "$checked" -gt 0 ] || { echo "  FAIL  nothing checked"; rc=1; }
done

printf '\n'
if [ "$rc" -ne 0 ]; then
    echo "roundtrip_check: FAILED"
else
    echo "roundtrip_check: imported RTL differs from upstream by naming only"
fi
exit $rc
