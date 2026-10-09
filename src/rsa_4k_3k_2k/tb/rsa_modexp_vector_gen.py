#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
"""Golden vector generator for rsa_modexp_tb.

Emits one vector per line, 7 whitespace-separated hex fields:

    base  exponent  n  n_prime_lsw  r_pow_1_mod_n  r_pow_2_mod_n  expected_result

The RTL computes base^exponent mod n using square-and-multiply-always over a
Montgomery multiplier, and expects R mod n, R^2 mod n and -n^-1 mod 2^RADIX to
be supplied by the caller (there is no on-chip precompute).

R = 2^(RADIX * S_NUM) where S_NUM = ceil(KEY_SIZE/RADIX) + 1, i.e. the same
oversized R the Montgomery array uses.  That extra word is what lets the array
skip the final conditional subtraction, so it must be matched here.

Usage:
    rsa_modexp_vector_gen.py <count> <key_size> <radix> [outfile] [--pub|--sec]

    --pub  exponent = 65537 (public-key op)
    --sec  exponent = a full-width random odd exponent (private-key op)
"""

import random
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rsa_montgomerymultiplier_model import n_prime, random_prime, ceil_div


def gen(count, key_size, radix, public, seed=0xC0FFEE):
    rnd = random.Random(seed ^ key_size ^ (1 if public else 2))
    s_num = ceil_div(key_size, radix) + 1
    r = 1 << (radix * s_num)

    out = []
    for _ in range(count):
        # Retry half-width prime pairs until their product has the full key width.
        while True:
            p = random_prime(key_size // 2)
            q = random_prime(key_size // 2)
            n = p * q
            if n.bit_length() == key_size and p != q:
                break

        base = rnd.randrange(1, n)
        if public:
            e = 65537
        else:
            # Vary secret exponent bits while keeping the test width fixed.
            e = rnd.randrange(1 << (key_size - 1), 1 << key_size) | 1

        out.append({
            'base': base,
            'exp': e,
            'n': n,
            'np': n_prime(n, radix),
            'r1': r % n,
            'r2': (r * r) % n,
            'res': pow(base, e, n),
        })
    return out


def gen_half(count, key_size, radix, seed=0xC0FFEE):
    """One CRT branch: a key_size/2-bit prime modulus and a same-width secret
    exponent, with the Montgomery context taken against the HALF R.

    This is exactly what tessera_rsa_modexp sees with half_in raised.  The modulus is a
    single prime rather than a product because that is what p and q are; nothing
    in the datapath cares, but generating it as a prime keeps the vector honest
    about what it models and lets the exponent be reduced mod (p-1) the way a
    real d_p is.

    Fields are emitted zero padded to the FULL key width so the TB reads them
    into its existing key_size-wide registers with no format change.  The upper
    half of every field is zero, which is also the invariant the half datapath
    relies on.
    """
    half = key_size // 2
    rnd = random.Random(seed ^ key_size ^ 3)
    s_num_h = ceil_div(half, radix) + 1
    r_h = 1 << (radix * s_num_h)

    out = []
    for _ in range(count):
        p = random_prime(half)
        # Choose an odd exponent below p-1 with a fixed half-width ladder length.
        while True:
            e = rnd.randrange(1 << (half - 1), 1 << half) | 1
            if e < p - 1:
                break
        base = rnd.randrange(1, p)
        out.append({
            'base': base,
            'exp': e,
            'n': p,
            'np': n_prime(p, radix),
            'r1': r_h % p,
            'r2': (r_h * r_h) % p,
            'res': pow(base, e, p),
        })
    return out


def write(vectors, key_size, radix, path):
    nib = key_size // 4
    np_nib = radix // 4
    with open(path, 'w') as f:
        # No comment lines: the TB reads the file with $fscanf("%h").
        for v in vectors:
            f.write("%0*X %0*X %0*X %0*X %0*X %0*X %0*X\n" % (
                nib, v['base'], nib, v['exp'], nib, v['n'],
                np_nib, v['np'], nib, v['r1'], nib, v['r2'], nib, v['res']))


def main(argv):
    if len(argv) < 4:
        print(__doc__)
        return 1
    count = int(argv[1])
    key_size = int(argv[2])
    radix = int(argv[3])
    half = '--half' in argv
    public = (not half) and ('--sec' not in argv)
    rest = [a for a in argv[4:] if not a.startswith('--')]
    kind = 'half' if half else ('pub' if public else 'sec')
    path = rest[0] if rest else \
        "test_vectors/rsa_modexp_%s_vectors_%d_key_%d_word_%d.hex" % (
            kind, count, key_size, radix)

    if half:
        vectors = gen_half(count, key_size, radix)
    else:
        vectors = gen(count, key_size, radix, public)
    write(vectors, key_size, radix, path)

    # Recheck the result and Montgomery constants.
    for v in vectors:
        assert v['res'] == pow(v['base'], v['exp'], v['n'])
        assert (v['np'] * v['n']) % (1 << radix) == ((1 << radix) - 1) % (1 << radix)
        if half:
            # Check half-width operands and Montgomery context.
            assert v['n'].bit_length() == key_size // 2
            assert v['exp'].bit_length() == key_size // 2
            s_num_h = ceil_div(key_size // 2, radix) + 1
            assert v['r1'] == (1 << (radix * s_num_h)) % v['n']
    print("wrote %d %s vectors (key=%d radix=%d) to %s" %
          (count, kind, key_size, radix, path))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))


def derive_public(sec_path, pub_path, key_size):
    """Re-key an existing --sec vector file to e=65537.

    Reuses the moduli (and therefore the expensive prime search) from the
    private-exponent vectors, so a public-op vector set is essentially free.
    """
    nib = key_size // 4
    rows = []
    for line in open(sec_path):
        line = line.strip()
        if not line:
            continue
        f = line.split()
        base, n = int(f[0], 16), int(f[2], 16)
        f[1] = "%0*X" % (nib, 65537)
        f[6] = "%0*X" % (nib, pow(base, 65537, n))
        rows.append(" ".join(f))
    with open(pub_path, 'w') as fh:
        fh.write("\n".join(rows) + "\n")
    print("wrote %d pub vectors to %s" % (len(rows), pub_path))
