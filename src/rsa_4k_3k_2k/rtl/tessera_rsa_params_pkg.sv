// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//======================================================================
//
// tessera_rsa_params_pkg.sv
// -----------------
// Single point of configuration for the RSA accelerator.
//
// RSA_KEY_SIZE_CONFIG selects 4096 (default), 3072 or 2048 bits at elaboration:
//
//     vcs +define+RSA_KEY_SIZE_CONFIG=3072 ...
//
// The systolic array requires odd S_NUM = ceil(KEY_SIZE/RADIX) + 1, with
// 2*(PE_UNITS+1)+1 == S_NUM.  Recheck this when changing the radix:
//       RADIX = 32:  4096 -> 129,  3072 -> 97,  2048 -> 65   (all odd, legal)
//       RADIX = 64:  4096 ->  65,  3072 -> 49,  2048 -> 33   (all odd, legal)
//       RADIX = 48:  4096 ->  87,  3072 -> 65,  2048 -> 44   (2048 EVEN, illegal)
//       RADIX = 96:  4096 ->  44                             (4096 EVEN, illegal)
//       RADIX = 128: 4096 ->  33,  3072 -> 25,  2048 -> 17   (all odd, legal)
//       RADIX = 256: 4096 ->  17,  3072 -> 13,  2048 ->  9   (all odd, legal)
//
// A Montgomery multiply costs 3*S_NUM+1 cycles.  Larger radices reduce cycles
// but increase total multiplier area and combinational delay.  The default is
// 64; use RSA_RADIX_CONFIG=32 if needed for timing closure.  Radices above 64
// can tile legally but are not qualified for timing or functional correctness.
//
//======================================================================

`ifndef RSA_KEY_SIZE_CONFIG
  `define RSA_KEY_SIZE_CONFIG 4096
`endif

`ifndef RSA_RADIX_CONFIG
  `define RSA_RADIX_CONFIG 64
`endif

// Build-time CRT enable.  Zero omits CRT sequencing, half-width contexts and
// Garner recombination.  Software discovers it through RSA_CONFIG.CRT_SUPPORTED.
`ifndef RSA_CRT_ENABLE_CONFIG
  `define RSA_CRT_ENABLE_CONFIG 0
`endif

// Public exponentiation window width W.  A fixed window uses W squarings and
// one table multiply: 1 + 1/W Montgomery multiplies per bit, with 2**W entries.
// Non-power-of-two widths use an elaboration-checked reciprocal division.
// Public and secret widths differ because short public exponents cannot
// amortize large precomputations.  The larger width determines table storage.
`ifndef RSA_WINDOW_BITS_PUB_CONFIG
  `define RSA_WINDOW_BITS_PUB_CONFIG 3
`endif

// Secret window width for full-width and dual-lane CRT ladders; must be at
// least the public width.  Larger windows trade table storage for fewer cycles.
// Equal widths remove full/dual widening.  A single half-width ladder packs
// two entries per slot and gains an extra bit without additional storage.
`ifndef RSA_WINDOW_BITS_SEC_CONFIG
  `define RSA_WINDOW_BITS_SEC_CONFIG 5
`endif

// Exponent-blinding headroom swept by MODEXP_SEC.  The D port retains 64 extra
// bits regardless of this setting.  Blinding uses d' = d + r*lambda(n).
// Headroom must fit the port and be a multiple of RSA_WINDOW_BITS.
// The default is zero because firmware does not yet supply blinded exponents.
// Constant time requires a build-time sweep length, never a length derived
// from d; tessera_rsa_modexp pads the final window.
`ifndef RSA_EXP_BLIND_BITS_CONFIG
  `define RSA_EXP_BLIND_BITS_CONFIG 0
`endif

// Words advanced per modular-doubling cycle in tessera_rsa_mont_const.  One grouped
// SWEEP_WORDS*RADIX-bit subtract avoids serial word-to-word borrow propagation.
// Must divide NWORDS_H = KEY_SIZE/(2*RADIX): at radix 64, 1/2/4/8 work for
// 4096/3072/2048; 16 fails at 3072.  A value of 1 gives a word-serial sweep.
// The default uses a 512-bit subtractor; timing is unmeasured.  Reduce to 4
// or 2 if needed for closure.
`ifndef RSA_MC_SWEEP_WORDS_CONFIG
  `define RSA_MC_SWEEP_WORDS_CONFIG 8
`endif

package tessera_rsa_params_pkg;

  // Default modulus / exponent width in bits.
  localparam int unsigned RSA_KEY_SIZE = `RSA_KEY_SIZE_CONFIG;

  // Montgomery multiplier word (digit) width in bits.
  localparam int unsigned RSA_RADIX    = `RSA_RADIX_CONFIG;

  // Derived Montgomery geometry, mirrored from tessera_rsa_montgomerymultiplier.sv.
  localparam int unsigned RSA_S_NUM         = ((RSA_KEY_SIZE + RSA_RADIX - 1) / RSA_RADIX) + 1;
  localparam int unsigned RSA_FULL_REG_SIZE = RSA_S_NUM * RSA_RADIX;
  localparam int unsigned RSA_PE_UNITS      = (RSA_S_NUM - 1) / 2 - 1;

  // Cycles for one Montgomery multiply, from the push_reg shift length.
  localparam int unsigned RSA_MM_CYCLES     = 3 * RSA_S_NUM;

  // Is the CRT private-key datapath built into this instance?
  localparam bit RSA_CRT_ENABLE = (`RSA_CRT_ENABLE_CONFIG != 0);

  // CRT branches exponentiate modulo half-width p and q.
  localparam int unsigned RSA_CRT_KEY_SIZE = RSA_KEY_SIZE / 2;

  // Public window geometry; widening is derived from the configured widths.
  localparam int unsigned RSA_WINDOW_BITS = `RSA_WINDOW_BITS_PUB_CONFIG;
  localparam int unsigned RSA_WINDOW_TBL  = 2 ** RSA_WINDOW_BITS;

  localparam int unsigned RSA_WINDOW_BITS_SEC = `RSA_WINDOW_BITS_SEC_CONFIG;

  // How many bits wider than the public window the secret ladders run.
  localparam int unsigned RSA_WIN_EXTRA_BITS =
      (RSA_WINDOW_BITS_SEC > RSA_WINDOW_BITS) ? (RSA_WINDOW_BITS_SEC - RSA_WINDOW_BITS)
                                              : 0;

  // Full and dual secret ladders share the widened table depth.
  localparam bit RSA_WIN_HI_EN   = (RSA_WIN_EXTRA_BITS != 0);
  localparam bit RSA_DUAL_WIN_HI = RSA_WIN_HI_EN;
  localparam bit RSA_SEC_WIN_HI  = RSA_WIN_HI_EN;

  // Fixed secret sweep length; the D port retains its 64-bit headroom.
  localparam int unsigned RSA_EXP_BLIND_BITS = `RSA_EXP_BLIND_BITS_CONFIG;
  localparam int unsigned RSA_EXP_LADDER_BITS = RSA_KEY_SIZE + RSA_EXP_BLIND_BITS;

  // Accumulator words advanced per cycle by tessera_rsa_mont_const's doubling sweep.
  localparam int unsigned RSA_MC_SWEEP_WORDS = `RSA_MC_SWEEP_WORDS_CONFIG;

  // Montgomery multiplies for one exponentiation over K exponent bits:
  //   1 (base -> Montgomery)
  // + RSA_WINDOW_TBL - 2   (table entries 2 .. 2**W-1; zero when W == 1)
  // + ceil(K/W) * (W + 1)  (the ladder itself)
  // + 1 (Montgomery -> normal)
  // Latency is a function of K and W only, never of the exponent value.
  function automatic int unsigned rsa_modexp_mm_ops(input int unsigned k_bits);
    return 1 + (RSA_WINDOW_TBL - 2)
             + ((k_bits + RSA_WINDOW_BITS - 1) / RSA_WINDOW_BITS) * (RSA_WINDOW_BITS + 1)
             + 1;
  endfunction

  //======================================================================
  // Register-interface constants
  //======================================================================

  // Core identification, ASCII.
  localparam logic [63:0] RSA_CORE_NAME    = 64'h0000_0000_0061_7372;  // "rsa"
  localparam logic [63:0] RSA_CORE_VERSION = 64'h0000_0000_3030_312e;  // "1.00"

  // Register aperture depths, always sized for RSA-4096 regardless of the
  // synthesised key size.
  localparam int unsigned RSA_MOD_REGS  = 128;
  localparam int unsigned RSA_A_REGS    = 128;
  localparam int unsigned RSA_B_REGS    = 128;
  localparam int unsigned RSA_E_REGS    = 4;
  localparam int unsigned RSA_D_REGS    = 132;   // key + 64 bits of blinding headroom
  localparam int unsigned RSA_RES_REGS  = 128;
  localparam int unsigned RSA_PROD_REGS = 256;   // an unreduced product is 2x the key
  // CRT operands occupy half the modulus aperture.
  localparam int unsigned RSA_P_REGS    = 64;
  localparam int unsigned RSA_Q_REGS    = 64;
  localparam int unsigned RSA_DP_REGS   = 64;
  localparam int unsigned RSA_DQ_REGS   = 64;
  localparam int unsigned RSA_QINV_REGS = 64;

  // tessera_rsa_ctrl folds the separate MUL bit and CTRL[3] CRT modifier into this enum.
  typedef enum logic [2:0] {
    CMD_NONE           = 3'b000,
    CMD_LDMOD          = 3'b001,
    CMD_MODEXP_PUB     = 3'b010,
    CMD_MODEXP_SEC     = 3'b011,
    CMD_MUL            = 3'b100,
    CMD_RESERVED       = 3'b101,  // any encoding the register map does not define
    CMD_MODEXP_SEC_CRT = 3'b110
  } rsa_cmd_e;

  // STATUS.ERROR bit positions.
  localparam int unsigned RSA_ERROR_BITS = 16;
  typedef enum logic [3:0] {
    ERR_BAD_CMD     = 4'd0,   // unsupported command encoding
    ERR_NO_CONTEXT  = 4'd1,   // no modulus context -- LDMOD has not been run
    ERR_BAD_MOD     = 4'd2,   // modulus even or less than 3
    ERR_BAD_BASE    = 4'd3,   // base does not fit the declared key length
    ERR_CRT_UNAVAIL = 4'd4,   // CRT requested but not built into this instance
    ERR_MOD_RANGE   = 4'd5,   // modulus top RADIX bits all ones
    ERR_CRT_FAIL    = 4'd7,   // CRT key refused before the operation started
    ERR_BAD_KEYLEN  = 4'd8,   // CTRL.KEY_LEN unsupported, reserved, or mismatched
    ERR_MOD_FIT     = 4'd9,   // modulus does not match the declared key length
    ERR_CRT_VERIFY  = 4'd10   // CRT verification failed after the operation ran
  } rsa_err_e;                // 6 is unused: the ladder length is derived in HW

  //======================================================================
  // Array geometry and runtime key length
  //
  // Derived from RSA_KEY_SIZE and RSA_RADIX at elaboration.
  //======================================================================

  // Top stage TS = effective_modulus_width/(2*RADIX) sets array geometry:
  // MOD_WORDS = 2*TS, S_NUM = 2*TS+1, MM_II = 4*TS+4.
  localparam int unsigned RSA_TOP_STAGE_FULL = RSA_KEY_SIZE / (2 * RSA_RADIX);
  localparam int unsigned RSA_TOP_STAGE_HALF = RSA_TOP_STAGE_FULL / 2;

  // One shortening step of the runtime key length, in bits and in top stages.
  localparam int unsigned RSA_KEYLEN_STEP = 1024;
  localparam int unsigned RSA_GEOM_STEP   = RSA_KEYLEN_STEP / (2 * RSA_RADIX);

  // Number of legal CTRL.KEY_LEN encodings, capped at four by the field width.
  localparam int unsigned RSA_N_KEYLEN =
      ((RSA_KEY_SIZE / RSA_KEYLEN_STEP) > 4) ? 4 : (RSA_KEY_SIZE / RSA_KEYLEN_STEP);

  // Absolute KEY_LEN encodings map to shortening steps from the built width.
  // Unsupported lengths map to a sentinel rejected by the width check.
  localparam int unsigned RSA_KEYLEN_UNSUP = 99;
  localparam int unsigned RSA_SH_2048 = (RSA_KEY_SIZE >= 2048)
      ? (RSA_KEY_SIZE - 2048) / RSA_KEYLEN_STEP : RSA_KEYLEN_UNSUP;
  localparam int unsigned RSA_SH_3072 = (RSA_KEY_SIZE >= 3072)
      ? (RSA_KEY_SIZE - 3072) / RSA_KEYLEN_STEP : RSA_KEYLEN_UNSUP;
  localparam int unsigned RSA_SH_4096 = (RSA_KEY_SIZE >= 4096)
      ? (RSA_KEY_SIZE - 4096) / RSA_KEYLEN_STEP : RSA_KEYLEN_UNSUP;

  // Half-table packing requires exactly RSA_KEY_SIZE/2 bits.  Sentinel 3
  // denotes no such runtime width; a 3072-bit build does not offer 1536.
  localparam int unsigned RSA_HALF_SHORTEN = (RSA_KEY_SIZE == 4096) ? 2 :
                                             (RSA_KEY_SIZE == 2048) ? 1 : 3;

endpackage
