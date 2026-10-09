# NIST ACVP known-answer test vectors

## What is in here

`RSA-SignaturePrimitive-2.0.internalProjection.json` — vendored **byte for byte
unmodified** from the NIST ACVP reference server so that its hash can be checked
against upstream directly.

| Field | Value |
|---|---|
| Upstream repo | `usnistgov/ACVP-Server` |
| Path | `gen-val/json-files/RSA-SignaturePrimitive-2.0/internalProjection.json` |
| Commit | `fb44dce5257aba23088256e63c9b950db6967610` (`RELEASE/v1.1.0.36`, 2024-10-07) |
| SHA-256 | `9800458e4529f239797e17e2b4aac6bcfd3b11b8132d25c4400aaf8540ddfe89` |

Re-fetch and verify with:

```sh
curl -sSL -o /tmp/ip.json \
  https://raw.githubusercontent.com/usnistgov/ACVP-Server/fb44dce5257aba23088256e63c9b950db6967610/gen-val/json-files/RSA-SignaturePrimitive-2.0/internalProjection.json
sha256sum /tmp/ip.json
diff /tmp/ip.json RSA-SignaturePrimitive-2.0.internalProjection.json
```

## Why the signature primitive and not SigGen / SigVer

RSASP1 (FIPS 186-5 §5.2.1) is defined as

    s = m^d mod n

with **no padding layer of any kind**.  That is precisely the operation
`tessera_rsa_modexp` implements, so a signature-primitive vector maps onto the RTL with no
interpretation step in between: any mismatch is an RTL bug, not a disagreement
about how EMSA-PKCS1-v1_5 or EMSA-PSS was applied.

The alternatives were considered and rejected:

- **RSA-SigGen / RSA-SigVer** publish only `n`, `e`, the message and the signature.
  They never publish `d`, so they can only exercise the *public* exponent path.
  They also require reproducing the padding to obtain the integer being
  exponentiated, which puts a second implementation between NIST's answer and our
  comparison.
- **RSA-KeyGen** does not exercise modexp at all.
- **RSA-decryptionPrimitive** is the right shape but ships 2048-bit cases only.

The signature primitive covers **2048, 3072 and 4096** — every size this core is
parameterised for.

## Structure of the file

Six test groups:

| tgId | modulo | keyMode | total | usable |
|---|---|---|---|---|
| 1 | 2048 | standard | 15 | 13 |
| 2 | 3072 | standard | 15 | 13 |
| 3 | 4096 | standard | 15 | 13 |
| 4 | 2048 | crt | 15 | 13 |
| 5 | 3072 | crt | 15 | 13 |
| 6 | 4096 | crt | 15 | 13 |

Each case carries `message`, `signature`, `n`, `e`, `d`, `p`, `q` and a
`testPassed` flag.

**The two excluded cases per group are not failures of ours.** ACVP deliberately
includes cases with `message >= n`, which RSASP1 requires an implementation to
*reject*.  They have no defined `m^d mod n` answer to compare against and are
outside the input domain of the Montgomery datapath, so the generator drops them
and asserts that `message >= n` was the only reason for every drop.

All usable cases use `e = 65537`, which is why they slot directly into the
existing `msb_index = 16` public pass in `rsa_modexp_tb`.

The `crt` groups are vendored but currently unused.  They become directly usable
if the CRT backlog item lands behind `RSA_CRT_ENABLE`, and cost nothing to keep.

## Regenerating the .hex vectors

```sh
cd src/rsa_4k_3k_2k/tb
python3 rsa_acvp_kat_gen.py --all
```

See `rsa_acvp_kat_gen.py` for the conversion, which re-derives `s = m^d mod n`
and `m = s^e mod n` for every vector before writing anything.
