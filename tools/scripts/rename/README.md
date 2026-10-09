# Tessera crypto import

Caliptra crypto engines vendored into Tessera, with a rename script per block.
Run every command below from the repository root.

## Pulling the latest update from caliptra-rtl / adams-bridge

Everything is done by `tools/scripts/rename/import_block.sh`. It clones (or
reuses) the upstream repo, checks out the branch recorded in the block's
`revinfo.yml`, re-copies the block, re-applies the `tessera_` prefix and rewrites
`src/<block>/revinfo.yml` with the new upstream commit.

```sh
# one block
./tools/scripts/rename/import_block.sh ecc

# every block
./tools/scripts/rename/import_block.sh all

# reuse a clone you already have instead of cloning again
./tools/scripts/rename/import_block.sh all --upstream ../caliptra-rtl

# pin a specific upstream commit/tag instead of the branch tip
./tools/scripts/rename/import_block.sh ecc --ref v2.1.0
```

Then review and commit:

```sh
git diff --stat
git add -A && git commit -m "Update ecc from caliptra-rtl"
```

`import_block.sh` runs the checks itself; if it prints `all checks passed`
the import is good.

Blocks: `aes` `ecc` `hmac512` `hmac256` `hmac_drbg` `mldsa_mlkem_all_levels`
`sha256` `sha256_masked` `sha3` `sha512` `sha512_masked`.
`mldsa_mlkem_all_levels` comes from the `adams-bridge` submodule, and `hmac256`
and `sha256_masked` from caliptra-rtl's `future` branch — both are handled
automatically.

## Directory names say what the block implements

Upstream directory names are engine names (`sha512`, `abr`). Tessera shelves
each block under the *capability* it provides, so the tree can be read without
knowing caliptra-rtl's vocabulary:

| upstream | Tessera |
|---|---|
| `src/aes` | `src/aes_all_modes` |
| `src/ecc` | `src/ecc_ecdsa_ecdhe` |
| `src/hmac` | `src/hmac_512_384` |
| `src/hmac256` | `src/hmac_256` |
| `src/hmac_drbg` | `src/hmac_drbg` (already a capability name) |
| `src/abr` (submodule) | `src/mldsa_mlkem_all_levels` |
| `src/sha256` | `src/sha2_256_all_modes` |
| `src/sha256_masked` | `src/sha2_256_all_modes_masked` |
| `src/sha3` | `src/sha3_shake_all_modes` |
| `src/sha512` | `src/sha2_512_384_all_modes` |
| `src/sha512_masked` | `src/sha2_512_384_all_modes_masked` |

A driver states this once, as a prefix swap:

```sh
UPSTREAM_BLOCK_DIR="src/ecc"
BLOCK_DIR="src/ecc_ecdsa_ecdhe"
```

`rc_run` maps every upstream subtree — delivery *and* collateral — through that
swap. The alternative, a hand-written `DEST_SUBTREES` and
`COLLATERAL_DEST_SUBTREES` per block, is two lists per driver that have to be
kept in step with the upstream arrays by hand, and nothing would catch them
drifting apart. A subtree that does not sit under `UPSTREAM_BLOCK_DIR` is an
error rather than a silent pass-through, so a block cannot half-move. An
explicit `DEST_SUBTREES` entry still wins, which is what
`mldsa_mlkem_all_levels` needs: its sources come from the `adams-bridge`
submodule, so there is no upstream path for a single swap to rewrite.

Note the **block names themselves are unchanged** — still `ecc`, `sha512`,
`hmac512`. `BLOCK` drives *identifiers* (`tessera_ecc_adder.sv`) and the
generated env header (`tessera_hmac512_config.svh`); only the directory is
capability-named. `VF_FILELIST` likewise stays an upstream path — only its
basename is reused, under `$BLOCK_DIR/config/`.

Two blocks also carry a *stem* that differs from the upstream one.

`hmac512`: caliptra-rtl calls the SHA-512 HMAC engine simply `hmac`, which
reads as a generic name next to `hmac256`. The repo-wide *stem policy* in
`rename_common.sh` (`RC_DEFAULT_STEM_RENAMES`) renames `hmac*` to `hmac512*`
on top of the `tessera_` prefix, so upstream `src/hmac/rtl/hmac_core.sv` lands as
`src/hmac_512_384/rtl/tessera_hmac512_core.sv`. `hmac_drbg` is exempt
(`RC_DEFAULT_STEM_KEEP`) — it is a shared DRBG, not a SHA-512 HMAC, and both
HMAC-512 and ECC reference it. The policy lives in the shared engine rather
than in `rename_hmac512.sh` because identifiers cross block boundaries: ECC
also references `hmac_param_pkg`, and all three imports have to spell the
renamed names the same way. Each `revinfo.yml` records the policy that was in
force under `policy.stem_renames` / `policy.stem_keep`.

## One import, one `revinfo.yml`, one directory

`hmac_drbg` is imported exactly once even though ECC instantiates it too —
vendoring it twice would put two copies of the same module in a Tessera
netlist. It used to be imported as a second pair of subtrees hanging off the
HMAC-512 driver, which got the ownership right but put the provenance record in
the wrong place: `src/hmac_drbg/` could only answer "where did this come from"
by pointing at `src/hmac_512_384/revinfo.yml`. A record that does not travel
with the directory it describes defeats the reason revinfo lives inside the
block at all, and the CI re-import loop — which iterates `src/*/revinfo.yml` —
had no entry of its own to re-run. It is now its own block, with its own
driver, filelist and revinfo; the consumers (`ecc`, and anything else that
instantiates it) still only rewrite the *reference*, via `EXTRA_RENAME_IDENTS`.

`revinfo.yml` is deliberately engine-level: it answers "where did this block
come from", which is one upstream commit — not one row per file. There is no
per-file manifest, because there is nothing for one to say. The list of files
*is* the committed tree, and git already content-addresses every one of them;
`roundtrip_check.sh` therefore enumerates `git ls-files` over the block's
declared subtrees and maps each path back to upstream by undoing the prefix and
the stem. That is strictly stronger than reading a recorded list, because a
file added locally can no longer escape the proof just by not being on it.

The one thing that cannot be recovered from the tree is which files the import
*generated* rather than vendored — the compile-order filelist, and the captured
environment-macro header where a block needs one. Those are declared under
`artifacts.generated`, and they are the only files exempt from the round-trip
proof. `verify_import.sh` checks the declaration is truthful (each one present
and committed), since an untruthful entry there would quietly excuse a file
from being checked.

`mldsa_mlkem_all_levels` shows the two knobs pulling in opposite directions:
its *directory* is renamed but its *identifiers* are not. Upstream calls the
engine `abr` ("Adams Bridge"), a codename that says nothing about ML-DSA,
ML-KEM, or the security levels covered, so the Tessera directory is named for
what the block implements. The identifiers keep the short upstream `abr_` stem
— a 22-character stem on all 222 identifiers in the block would cost far more
readability than it buys. Directory and stem are independent:
`BLOCK_DIR`/`DEST_SUBTREES` set the first, `RC_DEFAULT_STEM_RENAMES` the
second. Tying them together, as `hmac512` does, is a per-block choice.

## Seeing what changed upstream first

```sh
./tools/scripts/rename/upstream_diff.sh --block ecc --upstream ../caliptra-rtl
./tools/scripts/rename/upstream_diff.sh            # all blocks
```

Lists the upstream commits and files that changed since the commit in
`src/<block>/revinfo.yml`. `--upstream` can be omitted once
`import_block.sh` has populated `.upstream-cache/caliptra-rtl`.

## Other scripts

| Script | Purpose |
| --- | --- |
| `import_block.sh` | the one you run — copy + rename + verify |
| `rename_<block>.sh` | per-block rules; called by `import_block.sh` |
| `rename_common.sh` | shared engine behind the per-block scripts |
| `upstream_diff.sh` | what changed upstream since the last import |
| `verify_import.sh` | structural checks on the imported tree |
| `roundtrip_check.sh` | proves the copy differs from upstream by naming only |
| `check_filelists.sh` | every path in the filelists resolves |

## Rename policy

Rename what is **declared** in synthesizable RTL (modules, packages,
environment config macros). Rewrite **references** to those names everywhere.
Rename nothing else — testbench and UVMF generator inputs keep their upstream
names so they stay comparable with upstream.
