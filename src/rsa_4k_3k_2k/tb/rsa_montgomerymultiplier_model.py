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
"""
Executable RTL-structured model of the Caliptra ECC Montgomery multiplier.

Mirrors ../rtl/ecc_montgomerymultiplier.sv and ../rtl/ecc_pe_first.sv /
ecc_pe.sv / ecc_pe_final.sv as a two-phase (comb/posedge) cycle model, so it
reproduces the systolic schedule -- the `odd` toggle, the odd-dependent
b_array/p_array word slicing, t_reg -> p_internal assembly and push_reg ready
timing -- not merely the arithmetic result.

Uses:
  1. Golden-vector regression for ecc_montgomerymultiplier_tb.sv.
  2. Test-vector generator for that TB.  The TB comments reference a
     `gen_mm_test_vectors.py` which is not checked in; `--gen` restores that
     capability, emitting the same 6-field format the TB's read_test_vectors()
     parses (a, b, n, n_prime, product, index).
  3. Reference model for arbitrary #(REG_SIZE, RADIX) re-instantiations,
     including RSA-width moduli.
  4. Models a proposed non-reducing (plain 2*REG_SIZE product) mode -- see
     ecc_montgomerymultiplier_model_validation.md.

Usage:
    python3 ecc_montgomerymultiplier_model.py                 # full self-test
    python3 ecc_montgomerymultiplier_model.py --check-golden  # vs shipped .hex
    python3 ecc_montgomerymultiplier_model.py --gen N W R [FILE]
                                                              # N vectors,
                                                              # OPERAND_WIDTH=W,
                                                              # WORD_WIDTH=R

Exits nonzero on any failure.  Python 3.6 compatible.
"""
from __future__ import print_function
import os
import random
import sys
import time


def mask(w):
    return (1 << w) - 1 if w > 0 else 0


def ceil_div(a, b):
    return (a + b - 1) // b


def egcd(a, b):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q = a // b
        a, b = b, a - q * b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def inv_mod(a, m):
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("not invertible")
    return x % m


def n_prime(n, radix):
    b = 1 << radix
    return (-inv_mod(n, b)) & (b - 1)


def is_probable_prime(n, rounds=16):
    if n < 2:
        return False
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small:
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2
    # Test probable primality with random Miller-Rabin bases.
    for _ in range(rounds):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        ok = False
        for __ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                ok = True
                break
        if not ok:
            return False
    return True


def random_prime(bits):
    while True:
        n = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(n):
            return n


class EccPeFirst(object):
    def __init__(self, radix):
        self.RADIX = radix
        self.rmask = mask(radix)
        self.c_0_reg = 0
        self.sum_0_reg = 0
        self.m_temp_reg = 0
        self.s_reg = 0
        self.a_reg = 0
        self.a_out = 0
        self.m_out = 0
        self.c_out = 0
        self.mult_out_0 = self.mult_out_1 = self.mult_out_2 = 0
        self.res_0 = self.sum_0 = self.carry_0 = 0
        self.res_1 = self.carry_1 = self.c_0 = self.c_1 = 0
        self.m_temp = 0
        self.a_val = 0
        self.s_val = 0
        self.nexts = {}
        self.issue_count = 0
        self.zero_issue_count = 0

    def comb(self, a_in, b_in, p_in, s_in, n_prime_in, odd):
        self.s_val = s_in if odd else self.s_reg
        self.a_val = a_in if odd else self.a_reg
        self.mult_out_0 = self.a_val * b_in
        self.res_0 = (self.s_val + (self.mult_out_0 & self.rmask)) & mask(self.RADIX + 1)
        self.sum_0 = self.res_0 & self.rmask
        self.carry_0 = (self.res_0 >> self.RADIX) & 1
        self.mult_out_1 = n_prime_in * self.sum_0
        self.m_temp = self.mult_out_1 & self.rmask
        self.mult_out_2 = self.m_temp_reg * p_in
        self.res_1 = (self.sum_0_reg + (self.mult_out_2 & self.rmask)) & mask(self.RADIX + 1)
        self.carry_1 = (self.res_1 >> self.RADIX) & 1
        self.c_0 = ((self.mult_out_0 >> self.RADIX) + self.carry_0) & mask(self.RADIX + 1)
        self.c_1 = ((self.mult_out_2 >> self.RADIX) + self.carry_1) & mask(self.RADIX + 1)
        self.c_out_comb = (self.c_0_reg + self.c_1) & mask(self.RADIX + 1)
        return self.a_out, self.m_out, self.c_out

    def posedge(self, start_in, zeroize, reset_n, odd):
        if (not reset_n) or zeroize or start_in:
            self.nexts = dict(c_0_reg=0, sum_0_reg=0, m_temp_reg=0, s_reg=0, a_reg=0,
                              a_out=0, m_out=0)
        else:
            self.nexts = dict(s_reg=self.last_s_in, a_reg=self.last_a_in,
                              m_temp_reg=self.m_temp, c_0_reg=self.c_0,
                              sum_0_reg=self.sum_0, a_out=self.a_val, m_out=self.m_temp)
        # Model the RTL's combinational c_out = c_0_reg + c_1.
        self.nexts['c_out'] = 0 if ((not reset_n) or zeroize or start_in) else self.c_out_comb

    def latch_inputs(self, a_in, s_in):
        self.last_a_in = a_in
        self.last_s_in = s_in

    def commit(self):
        for k, v in self.nexts.items():
            setattr(self, k, v)


class EccPe(object):
    def __init__(self, radix):
        self.RADIX = radix
        self.rmask = mask(radix)
        self.a_out = 0
        self.m_out = 0
        self.s_out = 0
        self.c_out = 0
        self.mult0_out = 0
        self.mult1_out = 0
        self.res = 0
        self.res_LSW = 0
        self.res_MSW = 0
        self.nexts = {}

    def comb(self, a_in, b_in, p_in, m_in, s_in, c_in, odd):
        c_mux = self.c_out if odd else c_in
        s_mux = s_in if odd else self.s_out
        self.mult0_out = a_in * b_in
        self.mult1_out = p_in * m_in
        self.res = self.mult0_out + self.mult1_out + c_mux + s_mux
        self.res_LSW = self.res & self.rmask
        self.res_MSW = (self.res >> self.RADIX) & mask(self.RADIX + 1)
        self.last_a_in = a_in
        self.last_m_in = m_in
        return self.a_out, self.m_out, self.s_out, self.c_out

    def posedge(self, start_in, zeroize, reset_n, odd):
        if (not reset_n) or zeroize or start_in:
            self.nexts = dict(c_out=0, s_out=0, a_out=0, m_out=0)
        else:
            self.nexts = dict(c_out=self.res_MSW, s_out=self.res_LSW,
                              a_out=(self.last_a_in if odd else self.a_out),
                              m_out=(self.last_m_in if odd else self.m_out))

    def commit(self):
        for k, v in self.nexts.items():
            setattr(self, k, v)


class EccPeFinal(object):
    def __init__(self, radix):
        self.RADIX = radix
        self.rmask = mask(radix)
        self.s_out = 0
        self.c_out = 0
        self.mult0_out = 0
        self.mult1_out = 0
        self.res = 0
        self.res_LSW = 0
        self.res_MSW = 0
        self.nexts = {}

    def comb(self, a_in, b_in, p_in, m_in, s_in, c_in, odd):
        c_mux = self.c_out if odd else c_in
        s_mux = s_in if odd else self.s_out
        self.mult0_out = a_in * b_in
        self.mult1_out = p_in * m_in
        self.res = self.mult0_out + self.mult1_out + c_mux + s_mux
        self.res_LSW = self.res & self.rmask
        self.res_MSW = (self.res >> self.RADIX) & mask(self.RADIX + 1)
        return self.s_out, self.c_out

    def posedge(self, start_in, zeroize, reset_n, odd):
        if (not reset_n) or zeroize or start_in:
            self.nexts = dict(c_out=0, s_out=0)
        else:
            self.nexts = dict(c_out=self.res_MSW, s_out=self.res_LSW)

    def commit(self):
        for k, v in self.nexts.items():
            setattr(self, k, v)


class MontMultiplierRTL(object):
    def __init__(self, reg_size=384, radix=48, nonreducing=False):
        self.REG_SIZE = reg_size
        self.RADIX = radix
        self.S_NUM = ceil_div(reg_size, radix) + 1
        self.FULL_REG_SIZE = self.S_NUM * radix
        self.PE_UNITS = ((self.S_NUM - 1) // 2) - 1
        self.T_COUNT = 2 * (self.PE_UNITS + 1) + 1
        self.clean_geometry = (self.T_COUNT == self.S_NUM and self.PE_UNITS >= 0)
        self.rmask = mask(radix)
        self.fmask = mask(self.FULL_REG_SIZE)
        self.nonreducing = nonreducing
        self.first = EccPeFirst(radix)
        self.pes = [EccPe(radix) for _ in range(max(0, self.PE_UNITS))]
        self.final = EccPeFinal(radix)
        self.reset()

    def reset(self):
        self.a_reg = self.b_reg = self.p_reg = self.n_prime_reg = 0
        self.push_reg = 0
        self.push_reg_eq_zero_ff = 0
        self.odd = 0
        self.last_s_reg = 0
        self.t_reg = [0] * max(1, self.T_COUNT)
        self.t_subtracted_reg = [0] * max(1, self.T_COUNT)
        self.sub_b_o = [0] * max(1, self.T_COUNT)
        self.low_words = []
        self.low_shift_reg = 0
        self.start_seen = False
        self.cycle = 0
        self.ready_o = 0
        self.p_o = 0
        self.p_internal = 0
        self.p_subtracted_internal = 0
        self.last_reduction = 0
        self.dead_signal_nonzero = []
        self.mult_issues = 0
        self.zero_mult_issues = 0

    def word(self, value, idx):
        return (value >> (idx * self.RADIX)) & self.rmask

    def arrays(self):
        n = self.PE_UNITS + 2
        a_array = [0] * n
        b_array = [0] * n
        p_array = [0] * n
        a_array[0] = self.word(self.a_reg, 0)
        b_array[0] = self.word(self.b_reg, 0)
        p_array[0] = self.word(self.p_reg, 0)
        for j in range(1, n):
            if self.odd:
                b_array[j] = self.word(self.b_reg, 2 * j)
                p_array[j] = self.word(self.p_reg, 2 * j)
            else:
                b_array[j] = self.word(self.b_reg, 2 * j - 1)
                p_array[j] = self.word(self.p_reg, 2 * j - 1)
        return a_array, b_array, p_array

    def comb_all(self):
        a, b, p = self.arrays()
        s = [0] * (self.PE_UNITS + 2)
        c = [0] * (self.PE_UNITS + 2)
        # Inter-PE connections use current outputs, as in RTL continuous assignments.
        for i, pe in enumerate(self.pes):
            s[i] = pe.s_out
            c[i + 1] = pe.c_out
        s[self.PE_UNITS] = self.final.s_out
        c[self.PE_UNITS + 1] = self.final.c_out
        s[self.PE_UNITS + 1] = self.last_s_reg
        self.first.latch_inputs(a[0], s[0])
        self.first.comb(a[0], b[0], p[0], s[0], self.n_prime_reg, self.odd)
        c[0] = self.first.c_out_comb
        prev_a = self.first.a_out
        prev_m = self.first.m_out
        for i, pe in enumerate(self.pes):
            pe.comb(prev_a, b[i + 1], p[i + 1], prev_m, s[i + 1], c[i], self.odd)
            prev_a = pe.a_out
            prev_m = pe.m_out
        self.final.comb(prev_a, b[self.PE_UNITS + 1], p[self.PE_UNITS + 1], prev_m,
                        s[self.PE_UNITS + 1], c[self.PE_UNITS], self.odd)
        self.s_array = s
        self.c_array = c
        self.a_array = a
        self.b_array = b
        self.p_array = p

    def assemble(self):
        self.p_internal = 0
        self.p_subtracted_internal = 0
        for i, w in enumerate(self.t_reg):
            self.p_internal |= (w & self.rmask) << (i * self.RADIX)
        for i, w in enumerate(self.t_subtracted_reg):
            self.p_subtracted_internal |= (w & self.rmask) << (i * self.RADIX)
        self.last_reduction = 0 if self.nonreducing else (self.sub_b_o[-1] & 1)
        self.p_o = ((self.p_subtracted_internal if self.last_reduction else self.p_internal)
                    & mask(self.REG_SIZE))
        return self.p_o

    def posedge(self, start_i=False, opa_i=0, opb_i=0, n_i=0, n_prime_i=0, zeroize=False, reset_n=True):
        # Evaluate combinational logic using old flops and current start input.
        self.comb_all()
        push_old = self.push_reg
        push_eq_zero_old = 1 if push_old == 0 else 0
        # Observe the first PE's low-word tap before the clock edge.
        tap = self.first.res_1 & self.rmask
        if self.start_seen and (not self.nonreducing) and tap != 0:
            self.dead_signal_nonzero.append((self.cycle, tap))
        # Count three multiplies in the first PE and two per remaining PE per cycle.
        if self.start_seen or start_i or push_old:
            vals = [(self.first.a_val, self.b_array[0]), (self.n_prime_reg, self.first.sum_0),
                    (self.first.m_temp_reg, self.p_array[0])]
            for i, pe in enumerate(self.pes):
                vals.append((self.a_array[i + 1], self.b_array[i + 1]))
                vals.append((self.p_array[i + 1], (self.first.m_out if i == 0 else self.pes[i - 1].m_out)))
            vals.append(((self.a_array[self.PE_UNITS + 1] if self.PE_UNITS == 0 else (self.pes[-1].a_out if self.pes else self.first.a_out)), self.b_array[self.PE_UNITS + 1]))
            vals.append((self.p_array[self.PE_UNITS + 1], (self.pes[-1].m_out if self.pes else self.first.m_out)))
            self.mult_issues += len(vals)
            self.zero_mult_issues += sum(1 for x, y in vals if x == 0 or y == 0)
        # Prepare PE next states.
        self.first.posedge(start_i, zeroize, reset_n, self.odd)
        for pe in self.pes:
            pe.posedge(start_i, zeroize, reset_n, self.odd)
        self.final.posedge(start_i, zeroize, reset_n, self.odd)
        if (not reset_n) or zeroize:
            next_a = next_b = next_p = next_np = 0
            next_odd = 0
            next_push = 0
            next_last_s = 0
            next_t = [0] * self.T_COUNT
            next_ts = [0] * self.T_COUNT
            next_bo = [0] * self.T_COUNT
            next_low_words = []
            next_low_shift = 0
        elif start_i:
            zpad_masked_n = n_i & mask(self.REG_SIZE)
            next_a = opa_i & mask(self.REG_SIZE)
            next_b = opb_i & mask(self.REG_SIZE)
            next_p = zpad_masked_n
            next_np = 0 if self.nonreducing else (n_prime_i & self.rmask)
            next_odd = 1
            next_push = 1 << (3 * self.S_NUM - 1)
            next_last_s = 0
            next_t = list(self.t_reg)
            next_ts = list(self.t_subtracted_reg)
            next_bo = list(self.sub_b_o)
            next_low_words = []
            next_low_shift = 0
            self.start_seen = True
        else:
            next_a = self.a_reg
            if self.odd:
                next_a = (self.a_reg >> self.RADIX) & self.fmask
            next_b = self.b_reg
            next_p = self.p_reg
            next_np = self.n_prime_reg
            next_odd = 0 if self.odd else 1
            next_push = (push_old >> 1) & mask(3 * self.S_NUM)
            next_last_s = self.c_array[self.PE_UNITS + 1] & self.rmask
            # Combine current sums with registered borrows for final subtraction.
            sub_res = []
            new_bo = []
            for i in range(self.T_COUNT):
                bi = 1 if i == 0 else self.sub_b_o[i - 1]
                src = self.s_array[0] if i in (0, 1) else self.s_array[i >> 1]
                pres = self.word((~self.p_reg) & self.fmask, i)
                val = src + pres + bi
                sub_res.append(val & mask(self.RADIX + 1))
                new_bo.append((val >> self.RADIX) & 1)
            next_bo = new_bo
            next_t = list(self.t_reg)
            next_ts = list(self.t_subtracted_reg)
            for i in range(self.T_COUNT):
                idx = 2 * (self.PE_UNITS + 1) - i
                if idx >= 0 and ((push_old >> idx) & 1):
                    src = self.s_array[0] if i in (0, 1) else self.s_array[i >> 1]
                    next_t[i] = src & self.rmask
                    next_ts[i] = sub_res[i] & self.rmask
            next_low_words = list(self.low_words)
            next_low_shift = self.low_shift_reg
            # In non-reducing mode, the even phase retires the low word;
            # the odd phase still reflects the previous sum_0_reg.
            if self.nonreducing and (not self.odd) and len(next_low_words) < self.S_NUM:
                next_low_words.append(tap)
                next_low_shift = ((tap & self.rmask) << ((len(next_low_words) - 1) * self.RADIX)) | next_low_shift
        # Commit top and PEs.
        self.a_reg, self.b_reg, self.p_reg, self.n_prime_reg = next_a, next_b, next_p, next_np
        self.odd, self.push_reg, self.last_s_reg = next_odd, next_push, next_last_s
        self.t_reg, self.t_subtracted_reg, self.sub_b_o = next_t, next_ts, next_bo
        self.low_words, self.low_shift_reg = next_low_words, next_low_shift
        self.first.commit()
        for pe in self.pes:
            pe.commit()
        self.final.commit()
        # Detect completion from the new push_reg and its pre-edge zero flag.
        self.push_reg_eq_zero_ff = push_eq_zero_old if (reset_n and not zeroize) else 0
        push_eq_zero_new = 1 if self.push_reg == 0 else 0
        self.ready_o = 1 if (push_eq_zero_new and not self.push_reg_eq_zero_ff) else 0
        self.assemble()
        self.cycle += 1
        return self.ready_o

    def run(self, a, b, n, np, max_cycles=None):
        self.reset()
        self.posedge(True, a, b, n, np)
        retire = None
        if max_cycles is None:
            max_cycles = 3 * self.S_NUM + 8
        while self.cycle < max_cycles:
            if self.posedge(False):
                retire = self.cycle
                break
        if retire is None:
            raise RuntimeError("no ready pulse")
        return self.p_o, retire - 1  # latency cycles after the launch/start edge

    def nonreducing_product(self):
        # Join p_internal and the tapped low words at the FULL_REG_SIZE boundary.
        return (self.p_internal << self.FULL_REG_SIZE) | (self.low_shift_reg & self.fmask)


def mont_ref(a, b, n, reg_size, radix):
    s = ceil_div(reg_size, radix) + 1
    R = 1 << (s * radix)
    return (a * b * inv_mod(R % n, n)) % n


def format_hex(x):
    return "0x%x" % x


P256 = int("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
P384 = int("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16)
Q384 = int("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16)
P521 = (1 << 521) - 1


def edge_vectors(n):
    vals = [(0, 0), (0, 1 % n), (1 % n, 0), (1 % n, 1 % n),
            (n - 1, 1 % n), (1 % n, n - 1), (n - 1, n - 1)]
    return vals


def test_reduced_case(name, reg_size, radix, n, vectors=200):
    m = MontMultiplierRTL(reg_size, radix, False)
    if not m.clean_geometry:
        return dict(name=name, mode="RED", status="SKIP", detail="unclean geometry S_NUM=%d T_COUNT=%d" % (m.S_NUM, m.T_COUNT))
    np = n_prime(n, radix)
    cycles = set()
    for a, b in edge_vectors(n):
        got, cyc = m.run(a, b, n, np)
        exp = mont_ref(a, b, n, reg_size, radix) & mask(reg_size)
        cycles.add(cyc)
        if got != exp:
            return dict(name=name, mode="RED", status="FAIL", detail="edge mismatch a=%x b=%x got=%x exp=%x" % (a,b,got,exp))
        if m.dead_signal_nonzero:
            return dict(name=name, mode="RED", status="FAIL", detail="res_1 low nonzero %r" % (m.dead_signal_nonzero[:3],))
    for _ in range(vectors):
        a = random.randrange(0, n)
        b = random.randrange(0, n)
        got, cyc = m.run(a, b, n, np)
        exp = mont_ref(a, b, n, reg_size, radix) & mask(reg_size)
        cycles.add(cyc)
        if got != exp:
            return dict(name=name, mode="RED", status="FAIL", detail="random mismatch got=%x exp=%x a=%x b=%x" % (got,exp,a,b))
        if m.dead_signal_nonzero:
            return dict(name=name, mode="RED", status="FAIL", detail="res_1 low nonzero %r" % (m.dead_signal_nonzero[:3],))
    issues_per_active_cycle = 3 + 2 * (m.PE_UNITS + 1)
    # Start cycle plus cycles through ready are conservatively issue cycles in this model.
    return dict(name=name, mode="RED", status="PASS", detail="%d rand + edges" % vectors,
                s_num=m.S_NUM, full=m.FULL_REG_SIZE, cycles=sorted(cycles),
                issues=issues_per_active_cycle * list(cycles)[0], per_cycle=issues_per_active_cycle)


def test_nonreducing_case(name, reg_size, radix, vectors=500):
    m = MontMultiplierRTL(reg_size, radix, True)
    if not m.clean_geometry:
        return dict(name=name, mode="NONRED", status="SKIP", detail="unclean geometry S_NUM=%d T_COUNT=%d" % (m.S_NUM, m.T_COUNT))
    n_dummy = (1 << reg_size) - 1
    if n_dummy % 2 == 0:
        n_dummy -= 1
    np = 0
    cycles = set()
    max_high = 0
    maxprod = 0
    cap = (1 << m.FULL_REG_SIZE) - 1
    cases = [(0, 0), (0, 1), (1, 0), (1, 1), ((1 << reg_size) - 1, 1),
             (1, (1 << reg_size) - 1), ((1 << reg_size) - 1, (1 << reg_size) - 1)]
    for _ in range(vectors):
        cases.append((random.getrandbits(reg_size), random.getrandbits(reg_size)))
    for a, b in cases:
        _, cyc = m.run(a, b, n_dummy, np)
        prod = m.nonreducing_product()
        exp = a * b
        cycles.add(cyc)
        high = exp >> m.FULL_REG_SIZE
        max_high = max(max_high, high)
        maxprod = max(maxprod, exp)
        if prod != exp:
            # Include tapped words to diagnose alignment errors.
            low = sum((w & m.rmask) << (i * radix) for i, w in enumerate(m.low_words))
            return dict(name=name, mode="NONRED", status="FAIL",
                        detail="mismatch got=%x exp=%x p_internal=%x low=%x words=%s a=%x b=%x" % (prod, exp, m.p_internal, low, [hex(x) for x in m.low_words], a, b))
    issues_per_active_cycle = 3 + 2 * (m.PE_UNITS + 1)
    return dict(name=name, mode="NONRED", status="PASS", detail="%d rand + edges" % vectors,
                s_num=m.S_NUM, full=m.FULL_REG_SIZE, cycles=sorted(cycles),
                issues=issues_per_active_cycle * list(cycles)[0], per_cycle=issues_per_active_cycle,
                max_high=max_high, high_capacity=cap, max_product=maxprod,
                max_operands_overflow=(((1 << reg_size) - 1) * ((1 << reg_size) - 1)) >> m.FULL_REG_SIZE > cap)


def print_table(rows):
    print("\n%-30s %-7s %-6s %-12s %-10s %s" % ("case", "mode", "status", "cycles", "S/FULL", "detail"))
    print("-" * 100)
    for r in rows:
        cyc = ",".join(map(str, r.get('cycles', []))) if 'cycles' in r else "-"
        sf = "%s/%s" % (r.get('s_num', '-'), r.get('full', '-'))
        print("%-30s %-7s %-6s %-12s %-10s %s" % (r['name'], r['mode'], r['status'], cyc, sf, r['detail']))


VECTOR_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test_vectors')

# The TB parses 6 whitespace-separated hex fields per vector, in this order:
#   a, b, n, n_prime, product, index
# See ecc_montgomerymultiplier_tb.sv read_test_vectors() (values_per_test_vector = 6).
VALUES_PER_TEST_VECTOR = 6


def vector_filename(count, operand_width, word_width):
    """Matches the $sformatf() in ecc_montgomerymultiplier_tb.sv."""
    return "mm_test_vectors_%d_key_%d_word_%d.hex" % (count, operand_width, word_width)


def read_tb_vectors(path):
    vals = [int(tok, 16) for tok in open(path).read().split() if tok.strip()]
    out = []
    for i in range(0, len(vals) - (VALUES_PER_TEST_VECTOR - 1), VALUES_PER_TEST_VECTOR):
        a, b, n, np_, prod, _idx = vals[i:i + VALUES_PER_TEST_VECTOR]
        out.append((a, b, n, np_, prod))
    return out


def check_golden():
    """Cross-check the model against every mm_test_vectors_*.hex shipped in the repo.

    These were produced by the original (now absent) generator, so agreement is
    an independent check of the model rather than a self-consistency check.
    """
    if not os.path.isdir(VECTOR_DIR):
        print("no test_vectors/ directory at %s" % VECTOR_DIR)
        return 1
    files = sorted(f for f in os.listdir(VECTOR_DIR)
                   if f.startswith('mm_test_vectors_') and f.endswith('.hex'))
    if not files:
        print("no mm_test_vectors_*.hex found in %s" % VECTOR_DIR)
        return 1
    rc = 0
    print("%-44s %5s %6s %7s %s" % ("file", "vecs", "S_NUM", "cycles", "result"))
    print("-" * 78)
    for fn in files:
        try:
            _, _, _, count, _, ow, _, ww = fn[:-4].split('_')
            operand_width, word_width = int(ow), int(ww)
        except ValueError:
            print("%-44s  cannot parse geometry from filename -- skipped" % fn)
            continue
        vectors = read_tb_vectors(os.path.join(VECTOR_DIR, fn))
        m = MontMultiplierRTL(reg_size=operand_width, radix=word_width)
        if not m.clean_geometry:
            print("%-44s  unclean geometry S_NUM=%d T_COUNT=%d -- skipped"
                  % (fn, m.S_NUM, m.T_COUNT))
            continue
        bad, lat = 0, None
        for (a, b, n, np_, prod) in vectors:
            if np_ != n_prime(n, word_width):
                bad += 1
                continue
            got, lat = m.run(a, b, n, np_)
            if got != prod or mont_ref(a, b, n, operand_width, word_width) != prod:
                bad += 1
        status = "PASS" if bad == 0 else "FAIL (%d/%d)" % (bad, len(vectors))
        if bad:
            rc = 1
        print("%-44s %5d %6d %7s %s" % (fn, len(vectors), m.S_NUM, lat, status))
    return rc


def gen_vectors(count, operand_width, word_width, path=None, modulus=None):
    """Regenerate TB stimulus in the format read_test_vectors() expects.

    Replaces the `gen_mm_test_vectors.py` referenced but not checked in.
    Every emitted `product` is produced by the cycle model, so the vectors
    encode the RTL schedule, not just the arithmetic.
    """
    m = MontMultiplierRTL(reg_size=operand_width, radix=word_width)
    if not m.clean_geometry:
        raise SystemExit("geometry not supported by the RTL: OPERAND_WIDTH=%d WORD_WIDTH=%d "
                         "gives S_NUM=%d, T_COUNT=%d (S_NUM must be odd)"
                         % (operand_width, word_width, m.S_NUM, m.T_COUNT))
    if modulus is None:
        modulus = (1 << operand_width) - 5           # odd, top bits set
        while modulus % 2 == 0 or not is_probable_prime(modulus):
            modulus -= 2
    np_ = n_prime(modulus, word_width)
    if path is None:
        path = os.path.join(VECTOR_DIR, vector_filename(count, operand_width, word_width))

    # Lead with edge cases, then random operands; both must satisfy a, b < n.
    ops = [(0, 0), (0, modulus - 1), (1, 1), (1, modulus - 1), (modulus - 1, modulus - 1)]
    while len(ops) < count:
        ops.append((random.randrange(modulus), random.randrange(modulus)))
    ops = ops[:count]

    width_nibbles = (operand_width + 3) // 4
    # Match the shipped vectors' byte-rounded n_prime field.
    word_nibbles = ((word_width + 7) // 8) * 2
    lines = []
    for idx, (a, b) in enumerate(ops):
        product, _ = m.run(a, b, modulus, np_)
        assert product == mont_ref(a, b, modulus, operand_width, word_width), \
            "model disagrees with bignum reference on vector %d" % idx
        lines.append("%0*x" % (width_nibbles, a))
        lines.append("%0*x" % (width_nibbles, b))
        lines.append("%0*x" % (width_nibbles, modulus))
        lines.append("%0*x" % (word_nibbles, np_))
        lines.append("%0*x" % (width_nibbles, product))
        lines.append("%x" % idx)
    with open(path, 'w') as fh:
        fh.write("\n".join(lines))
    print("wrote %d vectors (OPERAND_WIDTH=%d WORD_WIDTH=%d S_NUM=%d) to %s"
          % (count, operand_width, word_width, m.S_NUM, path))
    print("set TEST_VECTOR_NUM=%d in ecc_montgomerymultiplier_tb.sv to consume it" % count)
    return 0


def gen_chain(count, operand_width, word_width, path=None, modulus=None):
    """Emit an overlapped-forwarding chain for rsa_montgomerymultiplier_tb.

    The chain is res = MM(res, res) run with reduce_i = 0, i.e. the exact
    shape of the modexp ladder's squarings.  With reduce_i = 0 the RTL emits
    p_internal truncated to MODULUS_WIDTH -- NOT the conditionally subtracted
    value -- and that truncated word is also what the forwarding path hands
    to the next multiply, so the expectation here must be modelled the same
    way or the chain would diverge for arithmetic reasons that have nothing
    to do with pipelining.
    """
    m = MontMultiplierRTL(reg_size=operand_width, radix=word_width)
    if not m.clean_geometry:
        raise SystemExit("geometry not supported by the RTL")
    if modulus is None:
        modulus = (1 << operand_width) - 5
        while modulus % 2 == 0 or not is_probable_prime(modulus):
            modulus -= 2
    np_ = n_prime(modulus, word_width)
    if path is None:
        path = os.path.join(VECTOR_DIR,
                            "rsa_mm_chain_vectors_key_%d_word_%d.hex"
                            % (operand_width, word_width))

    width_nibbles = (operand_width + 3) // 4
    word_nibbles = ((word_width + 7) // 8) * 2
    seed = random.randrange(modulus)

    lines = ["%0*x" % (width_nibbles, modulus),
             "%0*x" % (word_nibbles, np_),
             "%0*x" % (width_nibbles, seed)]
    x = seed
    for _ in range(count):
        m.run(x, x, modulus, np_)
        x = m.p_internal & mask(operand_width)
        lines.append("%0*x" % (width_nibbles, x))
    with open(path, 'w') as fh:
        fh.write("\n".join(lines) + "\n")
    print("wrote a %d-deep MM chain (OPERAND_WIDTH=%d WORD_WIDTH=%d) to %s"
          % (count, operand_width, word_width, path))
    return 0


def main():
    random.seed(0xC41197A)
    print("Python:", sys.version.split()[0])
    started = time.time()
    print("\n=== Golden vectors (ecc_montgomerymultiplier_tb.sv stimulus) ===")
    golden_rc = check_golden()
    print("\n=== Parameterized sweep ===")
    rows = []
    reduced = [
        ("P-256 prime r32", 256, 32, P256),
        ("P-256 prime r48", 256, 48, P256),
        ("P-384 prime r48", 384, 48, P384),
        ("P-384 order r48", 384, 48, Q384),
        ("P-521 prime r48", 521, 48, P521),
    ]
    # Generate RSA-style moduli. Use radices that produce clean odd S_NUM geometry.
    for name, bits, radix in [("RSA-2048 random r32", 2048, 32), ("RSA-3072 random r48", 3072, 48), ("RSA-4096 random r48", 4096, 48)]:
        p = random_prime(bits // 2)
        q = random_prime(bits // 2)
        reduced.append((name, bits, radix, p * q))
    reduced.append(("random 256 odd r48", 256, 48, random.getrandbits(256) | (1 << 255) | 1))
    for item in reduced:
        print("running", item[0]); sys.stdout.flush()
        rows.append(test_reduced_case(*item))
    for item in [("nonred 256 r48", 256, 48), ("nonred 384 r48", 384, 48)]:
        print("running", item[0]); sys.stdout.flush()
        rows.append(test_nonreducing_case(*item))
    print_table(rows)
    failures = [r for r in rows if r['status'] == 'FAIL']
    passes = [r for r in rows if r['status'] == 'PASS']
    print("\nMultiplier/cycle accounting:")
    seen = set()
    for r in passes:
        key = (r['mode'], r.get('s_num'), r.get('full'), r.get('per_cycle'), tuple(r.get('cycles', [])))
        if key in seen:
            continue
        seen.add(key)
        print("  %s S_NUM=%s FULL=%s: %s RADIXxRADIX issues/cycle, cycles=%s, issues/product=%s" %
              (r['mode'], r.get('s_num'), r.get('full'), r.get('per_cycle'), r.get('cycles'), r.get('issues')))
    print("\nDead-signal claim: PASS (res_1[RADIX-1:0] stayed zero in all reduced-mode PASS vectors).")
    for r in rows:
        if r['mode'] == 'NONRED' and r['status'] == 'PASS':
            print("Sizing %s: max observed high=0x%x; high capacity=(1<<%d)-1; max operands overflow=%s" %
                  (r['name'], r['max_high'], r['full'], r['max_operands_overflow']))
    print("Elapsed %.1fs" % (time.time() - started))
    return 1 if (failures or golden_rc) else 0


def cli(argv):
    if len(argv) > 1 and argv[1] == '--check-golden':
        return check_golden()
    if len(argv) > 1 and argv[1] == '--gen':
        if len(argv) < 5:
            print("usage: %s --gen COUNT OPERAND_WIDTH WORD_WIDTH [OUTFILE]" % argv[0])
            return 2
        random.seed(0xC41197A)
        out = argv[5] if len(argv) > 5 else None
        return gen_vectors(int(argv[2]), int(argv[3]), int(argv[4]), out)
    if len(argv) > 1 and argv[1] == '--gen-chain':
        if len(argv) < 5:
            print("usage: %s --gen-chain COUNT OPERAND_WIDTH WORD_WIDTH [OUTFILE]" % argv[0])
            return 2
        random.seed(0xC41197A)
        out = argv[5] if len(argv) > 5 else None
        return gen_chain(int(argv[2]), int(argv[3]), int(argv[4]), out)
    if len(argv) > 1:
        print(__doc__)
        return 2
    return main()


if __name__ == '__main__':
    sys.exit(cli(sys.argv))
