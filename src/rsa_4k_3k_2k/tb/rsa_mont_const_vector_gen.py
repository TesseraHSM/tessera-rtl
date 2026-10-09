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
#
# Golden RSA moduli and Montgomery constants for tessera_rsa_mont_const:
#
#   n_prime = (-n^-1) mod 2^RADIX
#   r1      = R   mod n
#   r2      = R^2 mod n      with R = 2^(RADIX * S_NUM)
#
# Emit one hex value per line, without comments, for the TB's $fscanf("%h"):
#
#   n        (KEY_SIZE/4 hex digits)
#   n_prime  (RADIX/4 hex digits)
#   r1       (KEY_SIZE/4 hex digits)
#   r2       (KEY_SIZE/4 hex digits)

import os
import sys
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rsa_montgomerymultiplier_model import n_prime, random_prime  # noqa: E402

import random


def s_num(key_size, radix):
    return (key_size + radix - 1) // radix + 1


def gen_modulus(key_size, rng):
    half = key_size // 2
    while True:
        p = random_prime(half)
        q = random_prime(half)
        if p == q:
            continue
        n = p * q
        if n.bit_length() == key_size:
            return n


def gen_half_modulus(key_size, rng):
    """A half-width modulus, i.e. one CRT prime, of exactly key_size/2 bits."""
    return random_prime(key_size // 2)


def main():
    radix = int(sys.argv[1]) if len(sys.argv) > 1 else 32
    count = 2
    out_dir = os.path.dirname(os.path.abspath(__file__))
    for key_size in (2048, 3072, 4096):
        rng = random.Random(0xC0FFEE ^ key_size)
        full = s_num(key_size, radix) * radix
        r = 1 << full
        path = os.path.join(
            out_dir, "test_vectors",
            "rsa_mont_const_vectors_%d_key_%d_word_%d.hex" % (count, key_size, radix))
        with open(path, "w") as f:
            for _ in range(count):
                n = gen_modulus(key_size, rng)
                f.write("%0*x\n" % (key_size // 4, n))
                f.write("%0*x\n" % (radix // 4, n_prime(n, radix)))
                f.write("%0*x\n" % (key_size // 4, r % n))
                f.write("%0*x\n" % (key_size // 4, (r * r) % n))
        print("wrote %s" % path)

        # CRT companions use half-width primes and R_half = 2^(radix * s_num_h).
        # Zero-pad to the full key width for the TB's existing register format.
        half_key = key_size // 2
        s_num_h = half_key // radix + 1
        r_h = 1 << (s_num_h * radix)
        path_h = os.path.join(
            out_dir, "test_vectors",
            "rsa_mont_const_vectors_half_%d_key_%d_word_%d.hex" % (count, key_size, radix))
        with open(path_h, "w") as f:
            for _ in range(count):
                ph = gen_half_modulus(key_size, rng)
                f.write("%0*x\n" % (key_size // 4, ph))
                f.write("%0*x\n" % (radix // 4, n_prime(ph, radix)))
                f.write("%0*x\n" % (key_size // 4, r_h % ph))
                f.write("%0*x\n" % (key_size // 4, (r_h * r_h) % ph))
        print("wrote %s" % path_h)


if __name__ == "__main__":
    main()
