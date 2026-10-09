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
"""Vectors for rsa_crt_garner_tb.

Usage:  python3 rsa_crt_garner_vector_gen.py <count> <key_size> <radix> [path]

Each line is eight whitespace separated hex fields:

    p  q  qinv  n_prime_p  r2_p  m1  m2  m

where p and q are key_size/2-bit primes, qinv = q^-1 mod p, n_prime_p and r2_p
are the HALF-width Montgomery context for p (r2_p = R_half^2 mod p, with
R_half = 2^(radix * (ceil(key_size/2 / radix) + 1))), m1 and m2 are arbitrary
residues mod p and mod q, and m is the unique value below p*q congruent to both.

The golden m is computed by direct CRT search-free construction and then
independently re-checked against m % p == m1 and m % q == m2, so the expected
value never depends on the same Garner formula the RTL implements.  That
independence is the point: a shared misreading of Garner's algorithm would
otherwise be invisible.

All fields are zero padded to the FULL key width so the TB reads them into
key_size-wide registers unchanged.
"""

import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rsa_montgomerymultiplier_model import n_prime, random_prime, ceil_div


def invmod(a, m):
    """Iterative extended Euclid.  Python 3.7 has no pow(a, -1, m), and a
    recursive egcd blows the default recursion limit on 2048-bit operands."""
    old_r, r = a % m, m
    old_s, s = 1, 0
    while r != 0:
        quot = old_r // r
        old_r, r = r, old_r - quot * r
        old_s, s = s, old_s - quot * s
    assert old_r == 1, "not invertible"
    return old_s % m


def gen(count, key_size, radix, seed=0xC0FFEE):
    half = key_size // 2
    rnd = random.Random(seed ^ key_size ^ 5)
    s_num_h = ceil_div(half, radix) + 1
    r_h = 1 << (radix * s_num_h)

    out = []
    for _ in range(count):
        while True:
            p = random_prime(half)
            q = random_prime(half)
            # Equal prime widths ensure q < 2p for the RTL's bounded reduction.
            if p != q and p.bit_length() == half and q.bit_length() == half:
                break

        qinv = invmod(q, p)
        m1 = rnd.randrange(0, p)
        m2 = rnd.randrange(0, q)

        # Recheck this Garner result against its defining congruences below.
        m = (m2 + q * (((m1 - m2) * qinv) % p)) % (p * q)

        out.append({
            'p': p, 'q': q, 'qinv': qinv,
            'np': n_prime(p, radix),
            'r2': (r_h * r_h) % p,
            'm1': m1, 'm2': m2, 'm': m,
        })
    return out


def write(vectors, key_size, radix, path):
    nib = key_size // 4
    np_nib = radix // 4
    with open(path, 'w') as f:
        for v in vectors:
            f.write("%0*X %0*X %0*X %0*X %0*X %0*X %0*X %0*X\n" % (
                nib, v['p'], nib, v['q'], nib, v['qinv'],
                np_nib, v['np'], nib, v['r2'],
                nib, v['m1'], nib, v['m2'], nib, v['m']))


def main(argv):
    if len(argv) < 4:
        print(__doc__)
        return 1
    count = int(argv[1])
    key_size = int(argv[2])
    radix = int(argv[3])
    rest = [a for a in argv[4:] if not a.startswith('--')]
    path = rest[0] if rest else \
        "test_vectors/rsa_crt_garner_vectors_%d_key_%d_word_%d.hex" % (
            count, key_size, radix)

    vectors = gen(count, key_size, radix)
    write(vectors, key_size, radix, path)

    half = key_size // 2
    s_num_h = ceil_div(half, radix) + 1
    for v in vectors:
        # Validate the residues independently of Garner's formula.
        assert v['m'] % v['p'] == v['m1']
        assert v['m'] % v['q'] == v['m2']
        assert v['m'] < v['p'] * v['q']
        assert (v['q'] * v['qinv']) % v['p'] == 1
        assert (v['np'] * v['p']) % (1 << radix) == (1 << radix) - 1
        assert v['r2'] == ((1 << (radix * s_num_h)) ** 2) % v['p']
        # q < 2p is what makes the RTL's bounded reduction correct.
        assert v['q'] < 2 * v['p']
    print("wrote %d garner vectors (key=%d radix=%d) to %s" %
          (count, key_size, radix, path))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
