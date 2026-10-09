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
"""NIST ACVP known-answer vectors for tessera_rsa_modexp / tessera_rsa_top.

Converts the vendored ACVP RSA signature-primitive vectors into the same 7-field
hex format `rsa_modexp_vector_gen.py` already emits, so the testbench reads them
with the existing `read_test_vectors()` task and no new parser:

    base  exponent  n  n_prime_lsw  r_pow_1_mod_n  r_pow_2_mod_n  expected_result

Why these vectors
-----------------
RSASP1 is `s = m^d mod n` with no padding layer, which is exactly what this core
computes.  Unlike the random vectors from `rsa_modexp_vector_gen.py` -- whose
golden value is Python's own `pow()`, i.e. a self-consistency check -- the answer
here comes from NIST.  See test_vectors/acvp/PROVENANCE.md.

Two passes are derived from each ACVP case, exercising both directions of the
same NIST-supplied key:

    sec:  base = m, exponent = d,     result = s     (private, full-width ladder)
    pub:  base = s, exponent = 65537, result = m     (public)

The pub direction is the RSAVP1 verification primitive, so it is equally a NIST
known answer and not something this script invented.

Montgomery pre-computation
--------------------------
The RTL takes R mod n, R^2 mod n and -n^-1 mod 2^RADIX from the caller (tessera_rsa_top
computes them on-chip with LDMOD; tessera_rsa_modexp does not).  R is the *oversized*
R = 2^(RADIX * S_NUM), S_NUM = ceil(KEY_SIZE/RADIX) + 1 -- the extra word is what
lets the array skip the final conditional subtraction, so it must match here.

Usage
-----
    rsa_acvp_kat_gen.py --all                 # every size x radix combination
    rsa_acvp_kat_gen.py <key_size> <radix>    # one combination
"""

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rsa_montgomerymultiplier_model import n_prime, ceil_div

HERE = os.path.dirname(os.path.abspath(__file__))
ACVP_DIR = os.path.join(HERE, 'test_vectors', 'acvp')
ACVP_JSON = os.path.join(ACVP_DIR,
                         'RSA-SignaturePrimitive-2.0.internalProjection.json')

# Pin the ACVP source to detect accidental vector changes.
ACVP_SHA256 = '9800458e4529f239797e17e2b4aac6bcfd3b11b8132d25c4400aaf8540ddfe89'
ACVP_COMMIT = 'fb44dce5257aba23088256e63c9b950db6967610'

KEY_SIZES = (2048, 3072, 4096)
RADICES = (32, 64)

# ACVP uses F4, matching the testbench's exp_msb_index = 16 public pass.
PUB_EXPONENT = 65537


def load_acvp():
    """Load the vendored ACVP file after checking it is the pinned revision."""
    if not os.path.exists(ACVP_JSON):
        raise SystemExit(
            "missing %s\nSee test_vectors/acvp/PROVENANCE.md for how to fetch it."
            % ACVP_JSON)

    with open(ACVP_JSON, 'rb') as f:
        raw = f.read()

    digest = hashlib.sha256(raw).hexdigest()
    if digest != ACVP_SHA256:
        raise SystemExit(
            "ACVP vector file does not match the pinned revision.\n"
            "  expected sha256 %s (upstream commit %s)\n"
            "  found    sha256 %s\n"
            "Refusing to generate known-answer tests from an unverified source."
            % (ACVP_SHA256, ACVP_COMMIT, digest))

    return json.loads(raw.decode('utf-8'))


def acvp_cases(key_size):
    """Usable standard-key cases for one modulus size, newest ACVP schema.

    Cases flagged testPassed == False are the deliberate `message >= n` entries,
    which RSASP1 requires implementations to reject.  They have no defined
    answer, so they are dropped -- but the reason is asserted rather than
    assumed, so that a future ACVP release which fails a case for some *other*
    reason cannot be silently discarded.
    """
    doc = load_acvp()
    cases = []

    for group in doc['testGroups']:
        if group['modulo'] != key_size:
            continue
        # Use standard-key cases; leave CRT groups for separate tests.
        if group.get('keyMode') != 'standard':
            continue

        for tc in group['tests']:
            n = int(tc['n'], 16)
            e = int(tc['e'], 16)
            d = int(tc['d'], 16)
            m = int(tc['message'], 16)

            # Validate rejection before reading the absent signature field.
            if not tc.get('testPassed'):
                assert m >= n, (
                    "ACVP tc%s (modulo %d) is marked failing for a reason other "
                    "than message >= n; re-read the vector set before dropping it"
                    % (tc['tcId'], key_size))
                assert not tc.get('signature'), (
                    "ACVP tc%s is marked failing yet carries a signature"
                    % tc['tcId'])
                continue

            s = int(tc['signature'], 16)

            assert e == PUB_EXPONENT, \
                "ACVP tc%s uses e=%d, not F4" % (tc['tcId'], e)
            assert n.bit_length() == key_size, \
                "ACVP tc%s modulus is %d bits, expected %d" % (
                    tc['tcId'], n.bit_length(), key_size)
            assert 0 < m < n, "ACVP tc%s message out of range" % tc['tcId']

            # Cross-check NIST's answers in both directions using the supplied key.
            assert pow(m, d, n) == s, \
                "ACVP tc%s: m^d mod n != s" % tc['tcId']
            assert pow(s, e, n) == m, \
                "ACVP tc%s: s^e mod n != m" % tc['tcId']

            cases.append({'tc': tc['tcId'], 'n': n, 'e': e, 'd': d,
                          'm': m, 's': s})

    if not cases:
        raise SystemExit("no usable ACVP cases for key size %d" % key_size)
    return cases


def to_vectors(cases, key_size, radix, kind):
    """Attach the Montgomery constants and pick the direction under test."""
    s_num = ceil_div(key_size, radix) + 1
    r = 1 << (radix * s_num)

    vectors = []
    for c in cases:
        n = c['n']
        if kind == 'sec':
            base, exp, res = c['m'], c['d'], c['s']
        else:
            base, exp, res = c['s'], c['e'], c['m']

        np = n_prime(n, radix)
        # -n^-1 mod 2^radix, the form the PE array consumes.
        assert (np * n) % (1 << radix) == (1 << radix) - 1

        vectors.append({'base': base, 'exp': exp, 'n': n, 'np': np,
                        'r1': r % n, 'r2': (r * r) % n, 'res': res,
                        'tc': c['tc']})
    return vectors


def write(vectors, key_size, radix, path):
    nib = key_size // 4
    np_nib = radix // 4
    with open(path, 'w') as f:
        # No comment lines: the TB reads the file with $fscanf("%h").
        for v in vectors:
            f.write("%0*X %0*X %0*X %0*X %0*X %0*X %0*X\n" % (
                nib, v['base'], nib, v['exp'], nib, v['n'],
                np_nib, v['np'], nib, v['r1'], nib, v['r2'], nib, v['res']))


def emit(key_size, radix):
    cases = acvp_cases(key_size)
    count = len(cases)
    written = []

    for kind in ('sec', 'pub'):
        vectors = to_vectors(cases, key_size, radix, kind)

        # Check the selected direction before emitting vectors.
        for v in vectors:
            assert pow(v['base'], v['exp'], v['n']) == v['res'], \
                "tc%s failed re-check (%s, key=%d)" % (v['tc'], kind, key_size)

        path = os.path.join(
            HERE, 'test_vectors',
            "rsa_modexp_kat_%s_vectors_%d_key_%d_word_%d.hex"
            % (kind, count, key_size, radix))
        write(vectors, key_size, radix, path)
        written.append(os.path.basename(path))

    print("key=%-5d radix=%-3d %2d NIST ACVP vectors -> %s"
          % (key_size, radix, count, ", ".join(written)))
    return count


def main(argv):
    if len(argv) >= 2 and argv[1] == '--all':
        for key_size in KEY_SIZES:
            for radix in RADICES:
                emit(key_size, radix)
        return 0

    if len(argv) < 3:
        print(__doc__)
        return 1

    emit(int(argv[1]), int(argv[2]))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
