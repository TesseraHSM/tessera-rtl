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
"""Full RSA-CRT key vectors for the CRT test in rsa_top_tb.

Usage:  python3 rsa_crt_vector_gen.py <count> <key_size> <radix> [path]

Each line is nine whitespace separated hex fields, all zero padded to the FULL
key width except qinv (also full width, it is < p so it fits):

    n  d  p  q  dp  dq  qinv  base  m

with

    n    = p*q, exactly key_size bits because p and q are each exactly
           key_size/2 bits (MSB set).  That is the same conformance rule
           tessera_rsa_ctrl's crt_key_ok enforces in hardware, and the same rule that
           makes q < 2p and so makes tessera_rsa_crt_garner's bounded reduction and the
           T_p = 2^(key_size/2) - p reduction identity correct.
    d    = e^-1 mod lcm(p-1, q-1), e = 65537
    dp   = d mod (p-1),  dq = d mod (q-1)
    qinv = q^-1 mod p
    base = a random value in [1, n)
    m    = base^d mod n

The golden m is computed by plain non-CRT modular exponentiation, so it never
depends on the CRT identity the RTL implements.  A shared misreading of CRT
would otherwise be invisible.  dp/dq/qinv are additionally cross-checked against
their defining congruences.
"""

import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rsa_montgomerymultiplier_model import random_prime

E = 65537


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


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def gen(count, key_size, radix, seed=0xC27D):
    half = key_size // 2
    rnd = random.Random(seed ^ key_size ^ 6)

    out = []
    for _ in range(count):
        while True:
            p = random_prime(half)
            q = random_prime(half)
            if p == q:
                continue
            # Equal prime widths ensure q < 2p for bounded CRT reduction.
            if p.bit_length() != half or q.bit_length() != half:
                continue
            if gcd(E, (p - 1) * (q - 1)) != 1:
                continue
            if q > p:
                p, q = q, p          # Keep the conventional p > q ordering.
            n = p * q
            if n.bit_length() != key_size:
                continue
            break

        lam = (p - 1) * (q - 1) // gcd(p - 1, q - 1)
        d = invmod(E, lam)
        dp = d % (p - 1)
        dq = d % (q - 1)
        qinv = invmod(q, p)
        base = rnd.randrange(1, n)
        m = pow(base, d, n)

        out.append({'n': n, 'd': d, 'p': p, 'q': q, 'dp': dp, 'dq': dq,
                    'qinv': qinv, 'base': base, 'm': m})
    return out


def write(vectors, key_size, path):
    nib = key_size // 4
    with open(path, 'w') as f:
        for v in vectors:
            f.write("%0*X %0*X %0*X %0*X %0*X %0*X %0*X %0*X %0*X\n" % (
                nib, v['n'], nib, v['d'], nib, v['p'], nib, v['q'],
                nib, v['dp'], nib, v['dq'], nib, v['qinv'],
                nib, v['base'], nib, v['m']))


def main(argv):
    if len(argv) < 4:
        print(__doc__)
        return 1
    count = int(argv[1])
    key_size = int(argv[2])
    radix = int(argv[3])
    rest = [a for a in argv[4:] if not a.startswith('--')]
    path = rest[0] if rest else \
        "test_vectors/rsa_crt_vectors_%d_key_%d_word_%d.hex" % (
            count, key_size, radix)

    vectors = gen(count, key_size, radix)
    write(vectors, key_size, path)

    half = key_size // 2
    for v in vectors:
        assert v['n'] == v['p'] * v['q']
        assert v['n'].bit_length() == key_size
        assert v['p'].bit_length() == half and v['q'].bit_length() == half
        assert v['q'] < 2 * v['p']
        assert v['qinv'] < v['p']
        assert (v['q'] * v['qinv']) % v['p'] == 1
        assert (E * v['d']) % ((v['p'] - 1) * (v['q'] - 1) //
                               gcd(v['p'] - 1, v['q'] - 1)) == 1
        assert v['dp'] == v['d'] % (v['p'] - 1)
        assert v['dq'] == v['d'] % (v['q'] - 1)
        # Verify the private/public round trip.
        assert pow(v['m'], E, v['n']) == v['base']
        # Cross-check CRT recombination against the non-CRT result.
        m1 = pow(v['base'] % v['p'], v['dp'], v['p'])
        m2 = pow(v['base'] % v['q'], v['dq'], v['q'])
        assert (m2 + v['q'] * (((m1 - m2) * v['qinv']) % v['p'])) == v['m']
    print("wrote %d CRT key vectors (key=%d radix=%d) to %s" %
          (count, key_size, radix, path))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
