#!/usr/bin/env bash
# Shared lookup for the per-block provenance records.
#
# Each vendored block carries its own revinfo *inside* the block directory:
#
#   src/ecc/revinfo.yml    provenance: upstream commit, subtrees, policy, manifest
#   src/ecc/revinfo.map    identifier rename map
#
# so that copying src/ecc/ anywhere carries the record of where it came from.
# The block name is read from the file rather than inferred from the directory,
# because a block may be vendored to a different path than it has upstream
# (BLOCK_DIR) -- caliptra-rtl's src/hmac lands at src/hmac_512_384, for example.
#
# Source this, then use ri_find / ri_path.

# ri_find <dest> -- print "<block> <path-to-revinfo.yml>" per imported block.
ri_find() {
    local dest="$1" r b
    while IFS= read -r r; do
        [ -e "$r" ] || continue
        b="$(sed -nE 's/^block:[[:space:]]*(.+)$/\1/p' "$r" | head -1)"
        [ -n "$b" ] || continue
        printf '%s %s\n' "$b" "$r"
    done < <(find "$dest/src" -mindepth 2 -maxdepth 2 -name revinfo.yml 2>/dev/null | sort)
}

# ri_path <dest> <block> -- print the revinfo.yml path for one block, or fail.
ri_path() {
    local dest="$1" block="$2" b r
    while read -r b r; do
        [ "$b" = "$block" ] && { printf '%s\n' "$r"; return 0; }
    done < <(ri_find "$dest")
    return 1
}
