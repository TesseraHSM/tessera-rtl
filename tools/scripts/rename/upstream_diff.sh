#!/usr/bin/env bash
#
# upstream_diff.sh -- "what changed in caliptra-rtl since we vendored this?"
#
#   ./tools/scripts/rename/upstream_diff.sh            # all blocks, summary
#   ./tools/scripts/rename/upstream_diff.sh --block ecc --patch
#
# This is the whole reason revinfo/<block>.revinfo.yml records a commit SHA:
# it lets you review the upstream changelog for exactly the subtrees you
# imported before deciding to re-run the import.
#
# Blocks vendored from a submodule (ABR) are reported per repository: --against
# names a ref in caliptra-rtl, while each submodule is compared against the
# branch recorded for it in revinfo.yml.

set -euo pipefail

# shellcheck source=revinfo_lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/revinfo_lib.sh"

DEST="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
UPSTREAM=""
BLOCK=""
AGAINST="origin/main"
PATCH=0

while [ $# -gt 0 ]; do
    case "$1" in
        --upstream) UPSTREAM="${2:?}"; shift 2 ;;
        --block)    BLOCK="${2:?}";    shift 2 ;;
        --against)  AGAINST="${2:?}";  shift 2 ;;
        --patch)    PATCH=1;           shift ;;
        --help|-h)  sed -n '2,12p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ -n "$UPSTREAM" ] || UPSTREAM="$DEST/.upstream-cache/caliptra-rtl"
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

for b in "${blocks[@]}"; do
    revinfo="$(ri_path "$DEST" "$b" || true)"
    sha="$(sed -nE 's/^[[:space:]]*commit:[[:space:]]*"([0-9a-f]+)".*/\1/p' "$revinfo" | head -1)"
    # subtrees are recorded as: - { upstream: "src/ecc/rtl", tessera: "src/ecc/rtl" }
    # The changelog is an *upstream* question, so pull the upstream side only.
    mapfile -t subtrees < <(sed -nE '/^  subtrees:/,/^  [a-z_]+:/ s/^    -.*upstream:[[:space:]]*"([^"]+)".*/\1/p' "$revinfo")
    # the collateral tier is imported too, so upstream changes there matter as
    # much as changes to the RTL. Read the upstream side of collateral_subtrees,
    # not artifacts.collateral_dirs -- the latter records *Tessera* paths, which
    # are not what you can ask an upstream repo about.
    mapfile -t cdirs < <(sed -nE '/^  collateral_subtrees:/,/^  [a-z_]+:/ s/^    -.*upstream:[[:space:]]*"([^"]+)".*/\1/p' "$revinfo")
    [ "${#cdirs[@]}" -eq 0 ] || subtrees+=("${cdirs[@]}")

    # A block can vendor from more than one repository, and a submodule can be
    # pinned independently of the superproject gitlink. Asking the superproject
    # about a submodule path only ever shows the gitlink moving, so each
    # recorded submodule gets its own query, in its own clone, against its own
    # branch.
    sub_paths=(); sub_brs=(); sub_shas=()
    while IFS='|' read -r sp sbr ssha; do
        [ -n "${ssha:-}" ] || continue
        sub_paths+=("$sp"); sub_brs+=("${sbr:-main}"); sub_shas+=("$ssha")
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

    printf '\n======================================================================\n'
    printf ' %s : imported at %s\n' "$b" "${sha:0:12}"
    printf ' subtrees: %s\n' "${subtrees[*]}"
    printf '======================================================================\n'

    # partition the recorded subtrees by owning repository
    own=()
    for s in "${subtrees[@]}"; do
        claimed=0
        for i in "${!sub_paths[@]}"; do
            case "$s" in "${sub_paths[$i]}"/*) claimed=1; break ;; esac
        done
        [ "$claimed" -eq 1 ] || own+=("$s")
    done

    report() {  # <repo dir> <from sha> <against ref> <paths...>
        local repo="$1" from="$2" against="$3"; shift 3
        # refspec, not a bare branch name: a submodule clone may not have a
        # remote-tracking ref for the branch revinfo recorded, and `fetch origin
        # <branch>` would only leave it in FETCH_HEAD.
        git -C "$repo" fetch --quiet --tags --prune origin \
            '+refs/heads/*:refs/remotes/origin/*' || true
        if [ "$(git -C "$repo" rev-parse "$against" 2>/dev/null || echo -)" = "$from" ]; then
            printf -- '-- %s: up to date with %s\n' "$(basename "$repo")" "$against"
            return
        fi
        printf -- '-- %s: %s..%s\n' "$(basename "$repo")" "${from:0:12}" "$against"
        git -C "$repo" log --oneline --no-decorate "$from..$against" -- "$@" \
            || echo "(no commits, or $from is not an ancestor of $against)"
        [ "$PATCH" -eq 1 ] || return 0
        printf '\n---- diff ----\n'
        git -C "$repo" diff --stat "$from..$against" -- "$@"
    }

    [ "${#own[@]}" -eq 0 ] || report "$UPSTREAM" "$sha" "$AGAINST" "${own[@]}"

    for i in "${!sub_paths[@]}"; do
        sp="${sub_paths[$i]}"
        rest=()
        for s in "${subtrees[@]}"; do
            case "$s" in "$sp"/*) rest+=("${s#"$sp"/}") ;; esac
        done
        [ "${#rest[@]}" -eq 0 ] || \
            report "$UPSTREAM/$sp" "${sub_shas[$i]}" "origin/${sub_brs[$i]}" "${rest[@]}"
    done
done
