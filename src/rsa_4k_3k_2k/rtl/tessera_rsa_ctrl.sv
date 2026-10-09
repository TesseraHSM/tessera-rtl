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
// tessera_rsa_ctrl
//
// Command sequencer between the RSA register file and the datapath.  It owns
// the hwif_in drive, the READY/VALID handshake, the interrupt pulses and the
// zeroize fan-out.
//
// Commands
//   LDMOD       latch RSA_MODULUS and derive the modulus context
//   MODEXP_PUB  RSA_A ^ RSA_E mod N; ladder length derived from RSA_E's MSB
//   MODEXP_SEC  RSA_A ^ RSA_D mod N; fixed configured secret sweep length
//   MUL         RSA_A * RSA_B into RSA_PRODUCT; no modulus context used or changed
//   MODEXP_SEC_CRT  private CRT exponentiation, built only with RSA_CRT_ENABLE
//
// Register words are big endian, word 0 most significant, so a key shorter than
// the aperture occupies the HIGH indices: RSA_MODULUS[128-KEY_WORDS .. 127].

module tessera_rsa_ctrl
  import tessera_rsa_params_pkg::*;
  import tessera_rsa_reg_pkg::*;
#(
    parameter int unsigned KEY_SIZE      = RSA_KEY_SIZE,
    parameter int unsigned RADIX         = RSA_RADIX,
    // Reserve 64 bits for exponent blinding (d + k*phi(n)).
    parameter int unsigned EXP_SIZE      = RSA_KEY_SIZE + 64
) (
    input  wire  clk,
    input  wire  reset_n,
    input  wire  cptra_pwrgood,

    input  rsa_reg__out_t hwif_out,
    output rsa_reg__in_t  hwif_in,

    output logic busy_o,
    output logic error_intr,
    output logic notif_intr,
    input  logic debugUnlock_or_scan_mode_switch
);

  // -------------------------------------------------------------------------
  // Local parameters
  // -------------------------------------------------------------------------
  localparam int unsigned KEY_WORDS   = KEY_SIZE / 32;
  localparam int unsigned EXP_WORDS   = EXP_SIZE / 32;
  localparam int unsigned E_BITS      = RSA_E_REGS * 32;

  localparam int unsigned EXP_IDX_W   = $clog2(EXP_SIZE);

  // Fixed secret sweep length; EXP_SIZE retains 64 bits of blinding headroom.
  localparam int unsigned LADDER_BITS = RSA_EXP_LADDER_BITS;

  // -------------------------------------------------------------------------
  // Runtime key length
  // -------------------------------------------------------------------------
  // Short operands are zero-extended in KEY_SIZE-wide buses and occupy the
  // high register indices of the big-endian apertures.  Runtime geometry uses
  // a top-stage index.  RSA_HALF_SHORTEN selects only half-table packing,
  // which requires exactly KEY_SIZE/2 bits, not any shortened width.
  typedef enum logic [2:0] {
    IDLE_ST,
    LDMOD_ST,
    MODEXP_ST,
    FINISH_ST
  } state_e;

  // -------------------------------------------------------------------------
  // Signals
  // -------------------------------------------------------------------------
  state_e                     state, state_next;

  logic                       zeroize_reg;
  rsa_cmd_e                   cmd_reg;
  rsa_cmd_e                   cmd_latched;
  rsa_cmd_e                   cmd_eff;

  logic [KEY_SIZE-1:0]        modulus_in;
  logic [KEY_SIZE-1:0]        base_in;
  logic [KEY_SIZE-1:0]        mul_b_in;
  logic [E_BITS-1:0]          e_in;
  logic [EXP_SIZE-1:0]        d_in;

  logic [KEY_SIZE-1:0]        n_latched;
  logic                       modctx_valid;
  // Context width tag: MODEXP must use the width that defined R and R^2.
  logic [1:0]                 modctx_shorten;

  // *_req is requested, *_lat is captured at acceptance, and only *_eff may
  // drive the datapath.
  logic [1:0]                 keylen_shorten;
  logic [1:0]                 keylen_shorten_lat;
  logic [1:0]                 keylen_shorten_eff;
  logic                       keylen_half_req;
  logic                       keylen_bad_width;
  int unsigned                keylen_sh_req;
  logic                       keylen_half_lat;
  logic                       keylen_half_eff;
  // Public ladder length follows the same request/latch/effective discipline.
  logic [EXP_IDX_W-1:0]       exp_len_req;
  logic [EXP_IDX_W-1:0]       exp_len_lat;
  logic [EXP_IDX_W-1:0]       exp_len_eff;
  logic [7:0]                 keylen_geom;
  // Per-CRT-lane top-stage index.  A lane is half the key.
  logic [7:0]                 crt_lane_geom;
  logic                       mod_fits;

  logic                       mc_start;
  logic                       mc_done;
  logic                       mc_busy;
  logic [RADIX-1:0]           mc_n_prime;
  logic [KEY_SIZE-1:0]        mc_r1;
  logic [KEY_SIZE-1:0]        mc_r2;
  // Lane 1 of the constant generator: the q context of a CRT LDMOD, derived in
  // the same pass as the p context.
  logic                       mc_mm_dual;
  logic [KEY_SIZE-1:0]        mc_mm_a1;
  logic [KEY_SIZE-1:0]        mc_mm_b1;
  logic [RADIX-1:0]           mc_n_prime1;
  logic [KEY_SIZE-1:0]        mc_r1_1;
  logic [KEY_SIZE-1:0]        mc_r2_1;
  // R^2 addition chain: tessera_rsa_mont_const borrows tessera_rsa_modexp's Montgomery array.
  logic                       mc_mm_half;
  logic [5:0]                 mc_mm_sq_rep;
  logic                       mc_mm_hold;
  logic                       mc_mm_req;
  logic [KEY_SIZE-1:0]        mc_mm_a;
  logic [KEY_SIZE-1:0]        mc_mm_b;

  logic                       me_start;
  logic                       me_done;
  logic [EXP_SIZE-1:0]        me_exponent;
  logic [EXP_IDX_W-1:0]       me_msb_index;
  logic                       me_exp_public;
  logic [KEY_SIZE-1:0]        me_result;
  logic [KEY_SIZE-1:0]        me_result1;
  logic [KEY_SIZE-1:0]        result_reg;
  logic                       result_we;
  logic [2*RSA_FULL_REG_SIZE-1:0] me_product;
  logic [2*KEY_SIZE-1:0]      product_reg;
  logic                       product_we;
  logic                       mul_mode;
  logic                       me_mm_mode;
  logic [KEY_SIZE-1:0]        me_base;
  logic [KEY_SIZE-1:0]        me_mul_b;
  logic [KEY_SIZE-1:0]        me_n;

  logic                       ready_reg;
  logic                       valid_reg;
  logic [RSA_ERROR_BITS-1:0]      error_reg;
  logic                       cmd_accept;
  logic                       cmd_reject;
  logic                       done_pulse;
  logic                       error_pulse;

  logic                       mod_is_usable;
  logic                       mod_in_range;
  logic                       base_in_range;
  // Do both MUL operands fit the selected width?  Only meaningful when a
  // shortening is requested; see the comment at mul_fits.
  logic                       mul_fits;
  logic                       base_fits;
  logic [KEY_SIZE-1:0]        base_reduced;
  // MUL product, re-assembled for the selected width.
  logic [2*KEY_SIZE-1:0]      mul_product;

  // ---- CRT ---------------------------------------------------------------
  // CRT control outputs are tied off when the datapath is not built.
  localparam int unsigned     HALF_SIZE  = KEY_SIZE / 2;
  localparam int unsigned     HALF_WORDS = KEY_WORDS / 2;

  logic [HALF_SIZE-1:0]       p_in, q_in, qinv_in, dp_in, dq_in;
  logic                       crt_key_ok;
  logic                       crt_ldmod_arm;
  logic                       crt_ldmod_start;
  logic                       crt_ctx_invalidate;
  logic                       crt_exp_start;
  logic                       op_is_crt;

  logic                       crt_active;
  logic                       crt_ctx_valid;
  logic                       crt_done;
  logic                       crt_fault;
  logic [KEY_SIZE-1:0]        crt_result;

  logic                       crt_mc_start;
  logic                       crt_mc_half;
  logic [KEY_SIZE-1:0]        crt_mc_n;
  logic                       crt_mc_dual;
  logic [KEY_SIZE-1:0]        crt_mc_n1;

  logic                       crt_me_start;
  logic                       crt_me_mul_mode;
  logic                       crt_me_mm_mode;
  logic                       crt_me_mm_half;
  logic                       crt_me_half;
  logic                       crt_me_exp_public;
  logic [KEY_SIZE-1:0]        crt_me_base;
  logic [KEY_SIZE-1:0]        crt_me_mul_b;
  logic [EXP_SIZE-1:0]        crt_me_exponent;
  logic [EXP_IDX_W-1:0]       crt_me_msb_index;
  logic [KEY_SIZE-1:0]        crt_me_n;
  logic [RADIX-1:0]           crt_me_n_prime;
  logic [KEY_SIZE-1:0]        crt_me_r1;
  logic [KEY_SIZE-1:0]        crt_me_r2;
  // Lane 1 of the dual-lane branch exponentiation.
  logic                       crt_me_dual;
  logic [KEY_SIZE-1:0]        crt_me_base1;
  logic [EXP_SIZE-1:0]        crt_me_exponent1;
  logic [KEY_SIZE-1:0]        crt_me_n1;
  logic [RADIX-1:0]           crt_me_n_prime1;
  logic [KEY_SIZE-1:0]        crt_me_r11;
  logic [KEY_SIZE-1:0]        crt_me_r21;

  // Shared-datapath drive, after the CRT mux.
  logic                       mc_start_sel;
  logic                       mc_half_sel;
  logic [7:0]                 mc_geom_sel;
  logic [7:0]                 mc_mm_geom;
  logic [KEY_SIZE-1:0]        mc_n_sel;
  logic                       mc_dual_sel;
  logic [KEY_SIZE-1:0]        mc_n1_sel;
  logic                       me_dual_sel;
  logic [KEY_SIZE-1:0]        me_base1_sel;
  logic [KEY_SIZE-1:0]        me_mul_b1_sel;
  logic [KEY_SIZE-1:0]        me_n1_sel;
  logic [RADIX-1:0]           me_n_prime1_sel;
  logic                       me_mm_half_sel;
  logic [5:0]                 me_mm_sq_rep_sel;
  logic                       me_half_sel;
  logic [7:0]                 me_geom_sel;
  logic [7:0]                 me_mm_geom_sel;
  logic [EXP_SIZE-1:0]        me_exponent_sel;
  logic [EXP_IDX_W-1:0]       me_msb_index_sel;
  logic                       me_exp_public_sel;
  logic [RADIX-1:0]           me_n_prime_sel;
  logic [KEY_SIZE-1:0]        me_r1_sel;
  logic [KEY_SIZE-1:0]        me_r2_sel;


  // Elaboration checks must remain visible to synthesis, not translate_off.
  if (LADDER_BITS > EXP_SIZE)
    $fatal(1, "tessera_rsa_ctrl: RSA_EXP_BLIND_BITS_CONFIG (%0d) exceeds the D aperture headroom (%0d)",
           RSA_EXP_BLIND_BITS, EXP_SIZE - KEY_SIZE);
  if ((RSA_EXP_BLIND_BITS % RSA_WINDOW_BITS) != 0)
    $fatal(1, "tessera_rsa_ctrl: RSA_EXP_BLIND_BITS_CONFIG (%0d) must be a multiple of RSA_WINDOW_BITS (%0d)",
                 RSA_EXP_BLIND_BITS, RSA_WINDOW_BITS);
  // Reject narrower secret windows rather than silently clamping configuration.
  if (RSA_WINDOW_BITS_SEC < RSA_WINDOW_BITS)
    $fatal(1, "tessera_rsa_ctrl: RSA_WINDOW_BITS_SEC_CONFIG (%0d) must be >= RSA_WINDOW_BITS_PUB_CONFIG (%0d)",
                 RSA_WINDOW_BITS_SEC, RSA_WINDOW_BITS);
  // DP/DQ have no blinding headroom, unlike D.  Reject CRT with blinding:
  // truncating dp+k*(p-1) could produce a faulted signature that exposes factors.
  // Wider DP/DQ apertures would exceed their current 256-byte slots.
  if (RSA_CRT_ENABLE && (RSA_EXP_BLIND_BITS != 0))
    $fatal(1, "tessera_rsa_ctrl: RSA_CRT_ENABLE_CONFIG and RSA_EXP_BLIND_BITS_CONFIG (%0d) cannot both be set -- RSA_DP/RSA_DQ are exactly half the key and carry no blinding headroom",
           RSA_EXP_BLIND_BITS);

        // -------------------------------------------------------------------------
  // Operand assembly: word 0 is MSW; shorter keys occupy high indices.
  // -------------------------------------------------------------------------
  always_comb begin
    modulus_in = '0;
    base_in    = '0;
    mul_b_in   = '0;
    for (int w = 0; w < KEY_WORDS; w++) begin
      // Map key-relative words to the right-aligned aperture.
      modulus_in[(KEY_WORDS-1-w)*32 +: 32] = hwif_out.RSA_MODULUS[RSA_MOD_REGS-KEY_WORDS+w].MODULUS.value;
      base_in   [(KEY_WORDS-1-w)*32 +: 32] = hwif_out.RSA_A     [RSA_A_REGS  -KEY_WORDS+w].A.value;
      mul_b_in  [(KEY_WORDS-1-w)*32 +: 32] = hwif_out.RSA_B     [RSA_B_REGS  -KEY_WORDS+w].B.value;
    end
  end

  always_comb begin
    e_in = '0;
    for (int w = 0; w < RSA_E_REGS; w++) begin
      e_in[(RSA_E_REGS-1-w)*32 +: 32] = hwif_out.RSA_E[w].E.value;
    end
  end

  always_comb begin
    d_in = '0;
    for (int w = 0; w < EXP_WORDS; w++) begin
      d_in[(EXP_WORDS-1-w)*32 +: 32] = hwif_out.RSA_D[RSA_D_REGS-EXP_WORDS+w].D.value;
    end
  end

  // Half-width CRT operands are right-aligned in RSA-4096-sized apertures.
  always_comb begin
    p_in    = '0;
    q_in    = '0;
    qinv_in = '0;
    dp_in   = '0;
    dq_in   = '0;
    for (int w = 0; w < HALF_WORDS; w++) begin
      p_in   [(HALF_WORDS-1-w)*32 +: 32] = hwif_out.RSA_P   [RSA_P_REGS   -HALF_WORDS+w].P.value;
      q_in   [(HALF_WORDS-1-w)*32 +: 32] = hwif_out.RSA_Q   [RSA_Q_REGS   -HALF_WORDS+w].Q.value;
      qinv_in[(HALF_WORDS-1-w)*32 +: 32] = hwif_out.RSA_QINV[RSA_QINV_REGS-HALF_WORDS+w].QINV.value;
      // DP and DQ have separate apertures without D's blinding headroom.
      dp_in  [(HALF_WORDS-1-w)*32 +: 32] = hwif_out.RSA_DP[RSA_DP_REGS-HALF_WORDS+w].DP.value;
      dq_in  [(HALF_WORDS-1-w)*32 +: 32] = hwif_out.RSA_DQ[RSA_DQ_REGS-HALF_WORDS+w].DQ.value;
    end
  end

  // -------------------------------------------------------------------------
  // CRT key-material preconditions
  //
  // Base reduction uses x mod p = MM_half(MM_full(x,r2_p), 2^(KEY/2)-p).
  // Prime top bits must be set so 2^(KEY/2)-p < p and Garner's q < 2p holds.
  // Oddness makes the Montgomery inverse exist; qinv must be below p.
  // Primality is not checked here; Bellcore verification checks the result,
  // not primality.
  //
  // Check the runtime lane width, not the built HALF_SIZE: each prime spans
  // keylen_geom RADIX words, with its top bit set and all higher words clear.
  logic [HALF_SIZE-1:0] p_lane_top_word, q_lane_top_word;
  logic                 pq_above_lane_clear;
  localparam int unsigned HALF_WORDS_R = HALF_SIZE / RADIX;
  always_comb begin
    p_lane_top_word     = '0;
    q_lane_top_word     = '0;
    pq_above_lane_clear = 1'b1;
    for (int w = 0; w < HALF_WORDS_R; w++) begin
      if (8'(w) == (keylen_geom - 8'd1)) begin
        p_lane_top_word = HALF_SIZE'(p_in[w*RADIX +: RADIX]);
        q_lane_top_word = HALF_SIZE'(q_in[w*RADIX +: RADIX]);
      end
      if (8'(w) >= keylen_geom)
        if ((p_in[w*RADIX +: RADIX] != '0) || (q_in[w*RADIX +: RADIX] != '0))
          pq_above_lane_clear = 1'b0;
    end
  end
  always_comb crt_key_ok = p_in[0] && q_in[0]
                        && p_lane_top_word[RADIX-1] && q_lane_top_word[RADIX-1]
                        && pq_above_lane_clear
                        && (qinv_in < p_in);

  // -------------------------------------------------------------------------
  // Command decode and operand checks
  // -------------------------------------------------------------------------
  always_comb begin
    zeroize_reg = hwif_out.RSA_CTRL.ZEROIZE.value || debugUnlock_or_scan_mode_switch;
    // Flatten the separate MUL bit and CTRL[3] CRT modifier into one opcode.
    // MUL takes priority on conflicting writes because it leaves context intact.
    if (hwif_out.RSA_CTRL.MUL.value) begin
      cmd_reg = CMD_MUL;
    end else begin
      unique case (hwif_out.RSA_CTRL.CTRL.value)
        4'b0000: cmd_reg = CMD_NONE;
        4'b0001: cmd_reg = CMD_LDMOD;
        4'b0010: cmd_reg = CMD_MODEXP_PUB;
        4'b0011: cmd_reg = CMD_MODEXP_SEC;
        4'b1011: cmd_reg = CMD_MODEXP_SEC_CRT;
        // Reserved encodings, including LDMOD_CRT (1001), raise ERR_BAD_CMD
        // rather than being silently ignored as CMD_NONE.
        default: cmd_reg = CMD_RESERVED;
      endcase
    end
  end

  // -------------------------------------------------------------------------
  // Runtime key length decode
  // -------------------------------------------------------------------------
  // Decode absolute 2048/3072/4096-bit lengths into shortening steps.
  // Unsupported and reserved selections map to a rejected sentinel, never a
  // rounded width.  Carrying KEY_LEN in CTRL prevents command-to-command
  // inheritance.  keylen_half_req selects packing only at exactly KEY_SIZE/2.
  always_comb begin
    unique case (hwif_out.RSA_CTRL.KEY_LEN.value)
      2'b00:   keylen_sh_req = RSA_SH_2048;
      2'b01:   keylen_sh_req = RSA_SH_3072;
      2'b10:   keylen_sh_req = RSA_SH_4096;
      default: keylen_sh_req = RSA_KEYLEN_UNSUP;
    endcase
    keylen_bad_width = (keylen_sh_req >= RSA_N_KEYLEN);
    keylen_shorten   = keylen_bad_width ? 2'b00 : 2'(keylen_sh_req);
    keylen_half_req  = !keylen_bad_width && (RSA_HALF_SHORTEN != 3)
                       && (keylen_shorten == 2'(RSA_HALF_SHORTEN));
  end

  // Freeze geometry at acceptance because the ladder reads it throughout.
  // This complements the register file's busy-write blocking.
  always_comb keylen_half_eff     = cmd_accept ? keylen_half_req : keylen_half_lat;
  always_comb keylen_shorten_eff  = cmd_accept ? keylen_shorten  : keylen_shorten_lat;
  // Freeze the derived public exponent length at the same boundary.
  always_comb exp_len_eff = cmd_accept ? exp_len_req : exp_len_lat;
  // Each 1024-bit shortening removes RSA_GEOM_STEP top stages.
  always_comb crt_lane_geom = keylen_geom >> 1;
  always_comb keylen_geom = 8'(RSA_TOP_STAGE_FULL)
                          - 8'(RSA_GEOM_STEP) * 8'(keylen_shorten_eff);

  // An RSA modulus must be odd (Montgomery reduction needs n^-1 mod 2^RADIX to
  // exist) and larger than 1 so that the accumulator seed 1 is already reduced.
  always_comb mod_is_usable = modulus_in[0] && (modulus_in > KEY_SIZE'(2));

  // Shortened moduli must have the declared MSB set and no higher bits.
  // This prevents truncation and ties secret sweep length to modulus width.
  // Native-width fit checks remain permissive.  Constant slices plus a mux
  // avoid a full-width barrel shifter.
  // In product_o={p_internal,low_reg}, p_internal starts at the built
  // KEY_SIZE+RADIX boundary even for shortened operations.
  localparam int unsigned MUL_FULL_REG = KEY_SIZE + RADIX;   // S_NUM * RADIX

  logic [3:0]                 mod_fits_s;
  logic [3:0]                 mul_fits_s;
  logic [3:0]                 base_fits_s;
  logic [3:0]                 mod_in_range_s;
  logic [EXP_IDX_W-1:0]       me_msb_s     [0:3];
  logic [2*KEY_SIZE-1:0]      mul_product_s[0:3];

  for (genvar gs = 0; gs < 4; gs++) begin : gen_keylen
    if (gs < int'(RSA_N_KEYLEN)) begin : g_sup
      // Effective modulus width for this shortening.
      localparam int unsigned EW   = KEY_SIZE - gs * RSA_KEYLEN_STEP;
      // Words of low_reg the multiplier retires at this width: S_NUM*RADIX.
      localparam int unsigned LOWW = EW + RADIX;

      if (gs == 0) begin : g_native
        assign mod_fits_s[gs]    = 1'b1;
        assign mul_fits_s[gs]    = 1'b1;
        assign base_fits_s[gs]   = 1'b1;
        assign mul_product_s[gs] = me_product[2*KEY_SIZE-1:0];
      end else begin : g_short
        assign mod_fits_s[gs]    = (modulus_in[KEY_SIZE-1:EW] == '0)
                                 && modulus_in[EW-1];
        assign base_fits_s[gs]   = (base_in [KEY_SIZE-1:EW] == '0);
        assign mul_fits_s[gs]    = (base_in [KEY_SIZE-1:EW] == '0)
                                 && (mul_b_in[KEY_SIZE-1:EW] == '0);
        // Pack the live 2*EW product bits, then zero-extend to the aperture.
        assign mul_product_s[gs] = {{(2*KEY_SIZE - 2*EW){1'b0}},
                                    me_product[MUL_FULL_REG +: EW - RADIX],
                                    me_product[LOWW-1:0]};
      end

      // Lazy-reduction port-width bound, taken at the RUNNING width.
      assign mod_in_range_s[gs] = ~(&modulus_in[EW-1 -: RADIX]);
      // Secret sweep length depends on public KEY_LEN, never d.
      assign me_msb_s[gs]       = EXP_IDX_W'(EW + RSA_EXP_BLIND_BITS - 1);
    end else begin : g_unsup
      // Fail-closed defaults for selections rejected by keylen_bad_width.
      assign mod_fits_s[gs]     = 1'b0;
      assign mul_fits_s[gs]     = 1'b0;
      assign mod_in_range_s[gs] = 1'b0;
      assign me_msb_s[gs]       = '0;
      assign mul_product_s[gs]  = '0;
    end
  end

  always_comb mod_fits = mod_fits_s[keylen_shorten];

  // MUL operands need only fit the declared width; requiring their MSBs would
  // reject valid small integers.  Higher bits would be silently truncated.
  always_comb mul_fits  = mul_fits_s [keylen_shorten];
  always_comb base_fits = base_fits_s[keylen_shorten];

  // Normalize bases in [n,2^KEY_LEN) with one subtract.  With a full-bit-length
  // modulus and a fitting base, base < 2n; shortened mode enforces these bounds.
  always_comb base_reduced = base_in_range ? base_in : (base_in - n_latched);

  // -------------------------------------------------------------------------
  // MUL product re-assembly
  // -------------------------------------------------------------------------
  // Product = low_reg + (p_internal << (effective_key_width+RADIX)).
  // Select live low words and accumulator bits around the fixed port boundary;
  // t_clr clears unused accumulator words to prevent stale residue.
  // Use the latched width at retirement and derive slices from module geometry.
  always_comb mul_product = mul_product_s[keylen_shorten_lat];

  // Lazy products satisfy u < n*(1+n/R) < n*(1+2^-RADIX), R=2^(KEY+RADIX).
  // Although 4n < R holds, result and forwarding ports still require u < 2^KEY.
  // Reject all-ones top RADIX bits, enforcing the sufficient bound
  // n < 2^KEY - 2^(KEY-RADIX).  Apply it at the running width to avoid truncation.
  always_comb mod_in_range = mod_in_range_s[keylen_shorten];


  // Select whether base normalization needs a subtraction.
  always_comb base_in_range = (base_in < n_latched);

  // Derive the public ladder bound from E's MSB and freeze it at acceptance.
  // e=0 selects index 0 and returns A^0 mod n = 1.
  always_comb begin
    exp_len_req = '0;
    for (int unsigned b = 0; b < E_BITS; b++)
      if (e_in[b]) exp_len_req = EXP_IDX_W'(b);
  end

  // -------------------------------------------------------------------------
  // Public bounds follow e; secret bounds follow configured key width and
  // blinding headroom, never the value of d.
  // -------------------------------------------------------------------------
  // CTRL.CTRL self-clears one cycle after it is consumed, but the ladder reads
  // its exponent port for the whole run, so the command has to be held.
  always_comb cmd_eff = cmd_accept ? cmd_reg : cmd_latched;

  always_comb begin
    // Fail closed: only MODEXP_PUB selects e and enables public shortcuts.
    if (cmd_eff == CMD_MODEXP_PUB) begin
      me_exponent   = EXP_SIZE'(e_in);
      me_msb_index  = exp_len_eff;
      // e is public, so a zero window may skip its multiply.
      me_exp_public = 1'b1;
    end else begin
      me_exponent   = d_in;
      // Fixed sweep at the running key width, independent of d.
      me_msb_index  = me_msb_s[keylen_shorten_eff];
      // d is secret: the ladder must stay unconditional.
      me_exp_public = 1'b0;
    end
  end

  // -------------------------------------------------------------------------
  // Command acceptance
  // -------------------------------------------------------------------------
  logic [RSA_ERROR_BITS-1:0] cmd_error;
  always_comb begin
    cmd_error = '0;
    unique case (cmd_reg)
      // No command, no preconditions.  Empty BLOCK, not empty statement,
      // so that lint W193 stays quiet.
      CMD_NONE: begin end
      CMD_LDMOD: begin
        // Reject unsupported widths before consuming width-dependent checks.
        if (keylen_bad_width)    cmd_error[ERR_BAD_KEYLEN] = 1'b1;
        else if (!mod_is_usable) cmd_error[ERR_BAD_MOD]   = 1'b1;
        else if (!mod_fits)      cmd_error[ERR_MOD_FIT]   = 1'b1;
        else if (!mod_in_range)  cmd_error[ERR_MOD_RANGE] = 1'b1;
      end
      CMD_MODEXP_PUB: begin
        if (keylen_bad_width)              cmd_error[ERR_BAD_KEYLEN]  = 1'b1;
        // Require a valid context with matching R geometry.
        else if (!modctx_valid)            cmd_error[ERR_NO_CONTEXT]  = 1'b1;
        else if (keylen_shorten != modctx_shorten)
                                           cmd_error[ERR_BAD_KEYLEN]  = 1'b1;
        else if (!base_fits)               cmd_error[ERR_BAD_BASE]    = 1'b1;
      end
      CMD_MODEXP_SEC: begin
        if (keylen_bad_width)              cmd_error[ERR_BAD_KEYLEN] = 1'b1;
        else if (!modctx_valid)            cmd_error[ERR_NO_CONTEXT] = 1'b1;
        else if (keylen_shorten != modctx_shorten)
                                           cmd_error[ERR_BAD_KEYLEN] = 1'b1;
        else if (!base_fits)               cmd_error[ERR_BAD_BASE]   = 1'b1;
      end
      // MUL checks operand width only; no modulus context is needed.
      CMD_MUL: begin
        if (keylen_bad_width)              cmd_error[ERR_BAD_KEYLEN] = 1'b1;
        else if (!mul_fits)                cmd_error[ERR_BAD_BASE]   = 1'b1;
      end
      CMD_MODEXP_SEC_CRT: begin
        // Half-width lanes require even keylen_geom >= 2.
        if (keylen_bad_width)              cmd_error[ERR_BAD_KEYLEN]  = 1'b1;
        else if (crt_lane_geom == 8'd0 || keylen_geom[0])
                                           cmd_error[ERR_BAD_KEYLEN]  = 1'b1;
        // The p/q contexts were built by an LDMOD at some shortening; running a
        // branch at a different one would exponentiate against the wrong width.
        else if (keylen_shorten != modctx_shorten)
                                           cmd_error[ERR_BAD_KEYLEN]  = 1'b1;
        else if (!RSA_CRT_ENABLE)           cmd_error[ERR_CRT_UNAVAIL] = 1'b1;
        // Require n for Bellcore verification and p/q for the secret branches.
        // LDMOD with malformed CRT material builds only n.
        else if (!modctx_valid)            cmd_error[ERR_NO_CONTEXT]  = 1'b1;
        else if (!crt_ctx_valid)           cmd_error[ERR_NO_CONTEXT]  = 1'b1;
        else if (!crt_key_ok)              cmd_error[ERR_CRT_FAIL]    = 1'b1;
        else if (!base_fits)               cmd_error[ERR_BAD_BASE]    = 1'b1;
      end
      default: cmd_error[ERR_BAD_CMD] = 1'b1;
    endcase
  end

  always_comb begin
    cmd_accept = (state == IDLE_ST) && (cmd_reg != CMD_NONE) && (cmd_error == '0);
    cmd_reject = (state == IDLE_ST) && (cmd_reg != CMD_NONE) && (cmd_error != '0);
  end

  // -------------------------------------------------------------------------
  // FSM
  // -------------------------------------------------------------------------
  always_comb begin
    state_next = state;
    unique case (state)
      IDLE_ST  : if (cmd_accept) state_next = (cmd_reg == CMD_LDMOD) ? LDMOD_ST : MODEXP_ST;
      // CRT completion covers all sub-operations, not an intermediate done pulse.
      LDMOD_ST : if (op_is_crt ? crt_done : mc_done) state_next = FINISH_ST;
      MODEXP_ST: if (op_is_crt ? crt_done : me_done) state_next = FINISH_ST;
      FINISH_ST:                 state_next = IDLE_ST;
      default  :                 state_next = IDLE_ST;
    endcase
  end

  // Arm CRT only when built and key preconditions pass; otherwise build n only
  // and leave p/q invalid.  Shortened CRT uses explicit per-lane geometry.
  always_comb crt_ldmod_arm   = RSA_CRT_ENABLE && crt_key_ok;
  always_comb crt_ldmod_start = cmd_accept && (cmd_reg == CMD_LDMOD) && crt_ldmod_arm;
  always_comb crt_exp_start   = RSA_CRT_ENABLE && cmd_accept && (cmd_reg == CMD_MODEXP_SEC_CRT);
  // An LDMOD that does not arm CRT must invalidate any previous p/q contexts.
  always_comb crt_ctx_invalidate = (cmd_accept || cmd_reject)
                                   && (cmd_reg == CMD_LDMOD) && !crt_ldmod_start;

  always_comb begin
    mc_start = cmd_accept && (cmd_reg == CMD_LDMOD) && !crt_ldmod_arm;
    // Commands and LDMOD's borrowed R^2 chain are mutually exclusive by state.
    me_start = (cmd_accept && (cmd_reg != CMD_LDMOD) && !crt_exp_start) || mc_mm_req;
    // Hold service ownership across internal relaunches, which resample context
    // and geometry.  The CRT controller waits while the generator owns the array.
    me_mm_mode = mc_mm_hold;
    mul_mode = (cmd_eff == CMD_MUL);

    me_base  = mc_mm_hold ? mc_mm_a : (mul_mode ? base_in : base_reduced);
    me_mul_b = mc_mm_hold ? mc_mm_b : mul_b_in;
    // During LDMOD, the live modulus is stable under busy-write protection.
    me_n     = (state == LDMOD_ST) ? modulus_in : n_latched;

    // Default shared-datapath drive; CRT overrides it below.
    mc_start_sel      = mc_start;
    // Use requested geometry unless the CRT controller selects a branch context.
    mc_half_sel       = keylen_half_eff;
    mc_geom_sel       = keylen_geom;
    mc_n_sel          = modulus_in;
    mc_dual_sel       = 1'b0;
    mc_n1_sel         = '0;
    // Lane 1 serves CRT branches unless borrowed by the constant generator.
    me_dual_sel       = crt_me_dual;
    me_base1_sel      = crt_me_base1;
    me_mul_b1_sel     = '0;
    me_n1_sel         = crt_me_n1;
    me_n_prime1_sel   = crt_me_n_prime1;
    me_mm_half_sel    = mc_mm_half;
    me_mm_geom_sel    = mc_mm_geom;
    me_mm_sq_rep_sel  = mc_mm_sq_rep;
    // Ladder geometry is separate from the generator's MM service geometry.
    me_half_sel       = keylen_half_eff;
    me_geom_sel       = keylen_geom;
    me_exponent_sel   = me_exponent;
    me_msb_index_sel  = me_msb_index;
    me_exp_public_sel = me_exp_public;
    me_n_prime_sel    = mc_n_prime;
    me_r1_sel         = mc_r1;
    me_r2_sel         = mc_r2;

    // -----------------------------------------------------------------------
    // CRT override, pruned in non-CRT builds.  The generator's R^2 chain has
    // priority while the CRT controller waits; use its selected p/q/n context,
    // not modulus_in, which always carries n.
    // -----------------------------------------------------------------------
    if (crt_active) begin
      mc_start_sel = crt_mc_start;
      mc_half_sel  = crt_mc_half;
      // Prime contexts use lane geometry; n uses full key geometry.
      // Test dual explicitly because these ports need not also assert half.
      mc_geom_sel  = (crt_mc_half || crt_mc_dual) ? crt_lane_geom : keylen_geom;
      mc_n_sel     = crt_mc_n;
      mc_dual_sel  = crt_mc_dual;
      mc_n1_sel    = crt_mc_n1;

      if (mc_mm_hold) begin
        me_n = crt_mc_n;
        // Dual derivation borrows lane 1 with q and its completed Newton inverse.
        me_dual_sel     = mc_mm_dual;
        // Retain the generator's captured mm_geom_out; do not override it.
        me_base1_sel    = mc_mm_a1;
        me_mul_b1_sel   = mc_mm_b1;
        me_n1_sel       = crt_mc_n1;
        me_n_prime1_sel = mc_n_prime1;
      end else begin
        me_start          = crt_me_start;
        me_mm_mode        = crt_me_mm_mode;
        mul_mode          = crt_me_mul_mode;
        me_mm_half_sel    = crt_me_mm_half;
        me_mm_geom_sel    = crt_me_mm_half ? crt_lane_geom : keylen_geom;
        // tessera_rsa_crt_ctrl's own service multiplies are single reductions, never
        // addition-chain runs.
        me_mm_sq_rep_sel  = 6'd0;
        me_half_sel       = crt_me_half;
        me_geom_sel       = crt_me_half ? crt_lane_geom : keylen_geom;
        me_base           = crt_me_base;
        me_mul_b          = crt_me_mul_b;
        me_n              = crt_me_n;
        me_n_prime_sel    = crt_me_n_prime;
        me_r1_sel         = crt_me_r1;
        me_r2_sel         = crt_me_r2;
        me_exponent_sel   = crt_me_exponent;
        me_msb_index_sel  = crt_me_msb_index;
        me_exp_public_sel = crt_me_exp_public;
      end
    end
  end

  always_ff @(posedge clk or negedge reset_n) begin
    if (!reset_n) begin
      state        <= IDLE_ST;
      n_latched    <= '0;
      modctx_valid <= 1'b0;
      result_reg   <= '0;
      result_we    <= 1'b0;
      product_reg  <= '0;
      product_we   <= 1'b0;
      valid_reg    <= 1'b0;
      error_reg    <= '0;
      done_pulse   <= 1'b0;
      error_pulse  <= 1'b0;
      cmd_latched  <= CMD_NONE;
      op_is_crt    <= 1'b0;
      keylen_half_lat    <= 1'b0;
      keylen_shorten_lat <= 2'b0;
      exp_len_lat        <= '0;
      modctx_shorten     <= 2'b0;
    end else if (zeroize_reg) begin
      state        <= IDLE_ST;
      n_latched    <= '0;
      modctx_valid <= 1'b0;
      result_reg   <= '0;
      result_we    <= 1'b0;
      product_reg  <= '0;
      product_we   <= 1'b0;
      valid_reg    <= 1'b0;
      error_reg    <= '0;
      done_pulse   <= 1'b0;
      error_pulse  <= 1'b0;
      cmd_latched  <= CMD_NONE;
      op_is_crt    <= 1'b0;
      keylen_half_lat    <= 1'b0;
      keylen_shorten_lat <= 2'b0;
      exp_len_lat        <= '0;
      modctx_shorten     <= 2'b0;
    end else begin
      state       <= state_next;
      result_we   <= 1'b0;
      product_we  <= 1'b0;
      done_pulse  <= 1'b0;
      error_pulse <= 1'b0;

      if (cmd_accept) begin
        cmd_latched <= cmd_reg;
        // Which unit reports completion for the operation now starting.
        op_is_crt   <= crt_ldmod_start | crt_exp_start;
        // Hold width and public exponent length throughout the operation.
        keylen_half_lat    <= keylen_half_req;
        keylen_shorten_lat <= keylen_shorten;
        exp_len_lat        <= exp_len_req;
      end

      // Clear the untargeted aperture so VALID cannot expose a stale result.
      if (cmd_accept && (cmd_reg == CMD_MUL)) begin
        result_reg <= '0;
        result_we  <= 1'b1;
      end
      if (cmd_accept && ((cmd_reg == CMD_MODEXP_PUB) || (cmd_reg == CMD_MODEXP_SEC)
                          || (cmd_reg == CMD_MODEXP_SEC_CRT))) begin
        product_reg <= '0;
        product_we  <= 1'b1;
      end

      // LDMOD produces no result; clear both apertures before setting VALID.
      if (cmd_accept && (cmd_reg == CMD_LDMOD)) begin
        result_reg  <= '0;
        result_we   <= 1'b1;
        product_reg <= '0;
        product_we  <= 1'b1;
      end

      if (cmd_accept || cmd_reject) begin
        // Any new command clears the previous result status and the error
        // code, so software never sees a stale VALID.
        valid_reg <= 1'b0;
        error_reg <= cmd_error;
      end

      if (cmd_reject) error_pulse <= 1'b1;

      // A new LDMOD invalidates the context *before* it runs, so a modulus
      // that fails validation cannot leave the previous context usable.
      if (cmd_accept && (cmd_reg == CMD_LDMOD)) begin
        modctx_valid <= 1'b0;
        n_latched    <= modulus_in;
        // Tag context geometry so later MODEXP commands can reject mismatches.
        modctx_shorten <= keylen_shorten;
      end
      if (cmd_reject && (cmd_reg == CMD_LDMOD)) begin
        modctx_valid <= 1'b0;
        n_latched    <= '0;
        modctx_shorten <= 2'b0;
      end

      if ((state == LDMOD_ST) && (op_is_crt ? crt_done : mc_done)) begin
        modctx_valid <= 1'b1;
        valid_reg    <= 1'b1;
        done_pulse   <= 1'b1;
      end

      if ((state == MODEXP_ST) && (op_is_crt ? crt_done : me_done)) begin
        if (op_is_crt) begin
          // Withhold faulted CRT results: one bad branch can expose a factor
          // via gcd(m^e-x,n).  On mismatch write zero, keep VALID low and signal
          // error, even if firmware ignores STATUS.
          result_reg <= crt_fault ? KEY_SIZE'(0) : crt_result;
          result_we  <= 1'b1;
          valid_reg  <= ~crt_fault;
          if (crt_fault) begin
            error_reg[ERR_CRT_VERIFY] <= 1'b1;
            error_pulse             <= 1'b1;
          end
          done_pulse <= 1'b1;
        end else begin
          if (cmd_latched == CMD_MUL) begin
            product_reg <= mul_product;
            product_we  <= 1'b1;
          end else begin
            result_reg <= me_result;
            result_we  <= 1'b1;
          end
          valid_reg  <= 1'b1;
          done_pulse <= 1'b1;
        end
      end
    end
  end

  // Drops in the acceptance cycle itself, one cycle before the FSM leaves
  // IDLE, so software polling STATUS cannot observe a false ready.
  always_comb ready_reg = (state == IDLE_ST) && !mc_busy && !cmd_accept;
  always_comb busy_o    = !ready_reg;

  // -------------------------------------------------------------------------
  // Datapath
  // -------------------------------------------------------------------------
  tessera_rsa_mont_const #(
      .MODULUS_BIT_WIDTH (KEY_SIZE),
      .WORD_BIT_WIDTH    (RADIX),
      .FULL_REG_SIZE     (RSA_FULL_REG_SIZE),
      // Build the second lane only for CRT.
      .DUAL_EN           (RSA_CRT_ENABLE)
  ) rsa_mont_const_i (
      .clk               (clk),
      .rst_n             (reset_n),
      .zeroize           (zeroize_reg),
      .start_in          (mc_start_sel),
      .n_in              (mc_n_sel),
      // Legacy half select alongside explicit runtime geometry.
      .half_i            (mc_half_sel),
      .geom_i            (mc_geom_sel),
      // Derive p and q contexts together in dual mode.
      .dual_i            (mc_dual_sel),
      .n1_in             (mc_n1_sel),
      .n_prime_lsw_out   (mc_n_prime),
      .r_pow_1_mod_n_out (mc_r1),
      .r_pow_2_mod_n_out (mc_r2),
      .n_prime1_lsw_out  (mc_n_prime1),
      .r_pow_1_mod_n1_out(mc_r1_1),
      .r_pow_2_mod_n1_out(mc_r2_1),
      .mm_req_out        (mc_mm_req),
      .mm_a_out          (mc_mm_a),
      .mm_b_out          (mc_mm_b),
      .mm_half_out       (mc_mm_half),
      .mm_geom_out       (mc_mm_geom),
      .mm_sq_rep_out     (mc_mm_sq_rep),
      .mm_hold_out       (mc_mm_hold),
      .mm_done_in        (me_done),
      .mm_result_in      (me_result),
      .mm_dual_out       (mc_mm_dual),
      .mm_a1_out         (mc_mm_a1),
      .mm_b1_out         (mc_mm_b1),
      .mm_result1_in     (me_result1),
      .done_out          (mc_done),
      .busy_out          (mc_busy)
  );

  tessera_rsa_modexp #(
      .MODULUS_BIT_WIDTH  (KEY_SIZE),
      .EXPONENT_BIT_WIDTH (EXP_SIZE),
      .WORD_BIT_WIDTH     (RADIX),
      // Build parallel half-width lanes only for CRT.
      .DUAL_EN            (RSA_CRT_ENABLE)
  ) rsa_modexp_i (
      .clk                   (clk),
      .rst_n                 (reset_n),
      .start_in              (me_start),
      .zeroize               (zeroize_reg),
      .mul_mode_in           (mul_mode),
      .mm_mode_in            (me_mm_mode),
      .mm_half_in            (me_mm_half_sel),
      .mm_geom_in            (me_mm_geom_sel),
      // Chained squarings of the service multiply.  A literal 0 for every
      // request that is not an R^2 addition-chain link.
      .mm_sq_rep_in          (me_mm_sq_rep_sel),
      // Half-table packing for a compatible shortened operation or CRT branch.
      .half_in               (me_half_sel),
      .geom_in               (me_geom_sel),
      .mul_b_in              (me_mul_b),
      .base_in               (me_base),
      .exponent_in           (me_exponent_sel),
      .exponent_msb_index_in (me_msb_index_sel),
      .exp_public_in         (me_exp_public_sel),
      .n_in                  (me_n),
      .n_prime_lsw_in        (me_n_prime_sel),
      .r_pow_1_mod_n_in      (me_r1_sel),
      .r_pow_2_mod_n_in      (me_r2_sel),
      // Lane 1 of the dual-lane CRT branch exponentiation.  Every one of these
      // is a literal constant in a non-CRT build.
      .dual_in               (me_dual_sel),
      .base1_in              (me_base1_sel),
      .exponent1_in          (crt_me_exponent1),
      .n1_in                 (me_n1_sel),
      .n_prime1_lsw_in       (me_n_prime1_sel),
      .r_pow_1_mod_n1_in     (crt_me_r11),
      .r_pow_2_mod_n1_in     (crt_me_r21),
      // Lane 1 operand of the single reducing service multiply, which the
      // constant generator drives while deriving the p and q contexts together.
      .mul_b1_in             (me_mul_b1_sel),
      .result_out            (me_result),
      .result1_out           (me_result1),
      .product_out           (me_product),
      .done_out              (me_done)
  );

  // -------------------------------------------------------------------------
  // Build-time CRT sequencing shares the array, ladder and constant generator.
  // The disabled branch ties off CRT outputs so its selection muxes fold away.
  // -------------------------------------------------------------------------
  generate
    if (RSA_CRT_ENABLE) begin : g_crt
      tessera_rsa_crt_ctrl #(
          .KEY_SIZE  (KEY_SIZE),
          .RADIX     (RADIX),
          .EXP_SIZE  (EXP_SIZE)
      ) rsa_crt_ctrl_i (
          .clk             (clk),
          .rst_n           (reset_n),
          .zeroize         (zeroize_reg),
          .geom_i          (keylen_geom),
          .ldmod_start_i   (crt_ldmod_start),
          .ctx_invalidate_i(crt_ctx_invalidate),
          .exp_start_i     (crt_exp_start),
          .n_i             (modulus_in),
          .base_i          (base_reduced),
          .p_i             (KEY_SIZE'(p_in)),
          .q_i             (KEY_SIZE'(q_in)),
          .qinv_i          (KEY_SIZE'(qinv_in)),
          .dp_i            (KEY_SIZE'(dp_in)),
          .dq_i            (KEY_SIZE'(dq_in)),
          .e_i             (EXP_SIZE'(e_in)),
          .e_msb_index_i   (exp_len_eff),
          .mc_start_o      (crt_mc_start),
          .mc_half_o       (crt_mc_half),
          .mc_n_o          (crt_mc_n),
          .mc_dual_o       (crt_mc_dual),
          .mc_n1_o         (crt_mc_n1),
          .mc_done_i       (mc_done),
          .mc_n_prime_i    (mc_n_prime),
          .mc_r1_i         (mc_r1),
          .mc_r2_i         (mc_r2),
          .mc_n_prime1_i   (mc_n_prime1),
          .mc_r1_1_i       (mc_r1_1),
          .mc_r2_1_i       (mc_r2_1),
          .me_start_o      (crt_me_start),
          .me_mul_mode_o   (crt_me_mul_mode),
          .me_mm_mode_o    (crt_me_mm_mode),
          .me_mm_half_o    (crt_me_mm_half),
          .me_half_o       (crt_me_half),
          .me_exp_public_o (crt_me_exp_public),
          .me_base_o       (crt_me_base),
          .me_mul_b_o      (crt_me_mul_b),
          .me_exponent_o   (crt_me_exponent),
          .me_msb_index_o  (crt_me_msb_index),
          .me_n_o          (crt_me_n),
          .me_n_prime_o    (crt_me_n_prime),
          .me_r1_o         (crt_me_r1),
          .me_r2_o         (crt_me_r2),
          .me_dual_o       (crt_me_dual),
          .me_base1_o      (crt_me_base1),
          .me_exponent1_o  (crt_me_exponent1),
          .me_n1_o         (crt_me_n1),
          .me_n_prime1_o   (crt_me_n_prime1),
          .me_r11_o        (crt_me_r11),
          .me_r21_o        (crt_me_r21),
          .me_done_i       (me_done),
          .me_result_i     (me_result),
          .me_result1_i    (me_result1),
          // Drop Montgomery padding from the architectural product slice.
          .me_product_i    (me_product[2*KEY_SIZE-1:0]),
          .crt_active_o    (crt_active),
          .ctx_valid_o     (crt_ctx_valid),
          .result_o        (crt_result),
          .done_o          (crt_done),
          .fault_o         (crt_fault)
      );
    end else begin : g_no_crt
      always_comb begin
        crt_active        = 1'b0;
        crt_ctx_valid     = 1'b0;
        crt_done          = 1'b0;
        crt_fault         = 1'b0;
        crt_result        = '0;
        crt_mc_start      = 1'b0;
        crt_mc_half       = 1'b0;
        crt_mc_n          = '0;
        crt_mc_dual       = 1'b0;
        crt_mc_n1         = '0;
        crt_me_start      = 1'b0;
        crt_me_mul_mode   = 1'b0;
        crt_me_mm_mode    = 1'b0;
        crt_me_mm_half    = 1'b0;
        crt_me_half       = 1'b0;
        crt_me_exp_public = 1'b0;
        crt_me_base       = '0;
        crt_me_mul_b      = '0;
        crt_me_exponent   = '0;
        crt_me_msb_index  = '0;
        crt_me_n          = '0;
        crt_me_n_prime    = '0;
        crt_me_r1         = '0;
        crt_me_r2         = '0;
        crt_me_dual       = 1'b0;
        crt_me_base1      = '0;
        crt_me_exponent1  = '0;
        crt_me_n1         = '0;
        crt_me_n_prime1   = '0;
        crt_me_r11        = '0;
        crt_me_r21        = '0;
      end
    end
  endgenerate

  // -------------------------------------------------------------------------
  // Register file drive
  // -------------------------------------------------------------------------
  always_comb hwif_in.reset_b      = reset_n;
  always_comb hwif_in.hard_reset_b = cptra_pwrgood;
  always_comb hwif_in.rsa_ready    = ready_reg;
  // Do not store CRT factors on instances that cannot use them.
  always_comb hwif_in.rsa_crt_key_we = ready_reg && RSA_CRT_ENABLE;

  always_comb hwif_in.RSA_NAME[0].NAME.next       = RSA_CORE_NAME[31:0];
  always_comb hwif_in.RSA_NAME[1].NAME.next       = RSA_CORE_NAME[63:32];
  always_comb hwif_in.RSA_VERSION[0].VERSION.next = RSA_CORE_VERSION[31:0];
  always_comb hwif_in.RSA_VERSION[1].VERSION.next = RSA_CORE_VERSION[63:32];

  always_comb hwif_in.RSA_STATUS.READY.next = ready_reg;
  always_comb hwif_in.RSA_STATUS.VALID.next = valid_reg;
  always_comb hwif_in.RSA_STATUS.ERROR.next = error_reg;
  always_comb hwif_in.RSA_STATUS.MODULUS_VALID.next = modctx_valid;
  always_comb hwif_in.RSA_CONFIG.CRT_SUPPORTED.next = RSA_CRT_ENABLE;

  // Consume the command in the cycle it is acted on -- including a rejected
  // one -- so the FSM cannot re-enter it.
  always_comb hwif_in.RSA_CTRL.CTRL.hwclr = cmd_accept | cmd_reject;
  // MUL self-clears on the same acceptance/rejection event.
  always_comb hwif_in.RSA_CTRL.MUL.hwclr  = cmd_accept | cmd_reject;
  // The declared width retires with the command it was declared for, so the
  // next command cannot inherit it.
  always_comb hwif_in.RSA_CTRL.KEY_LEN.hwclr = cmd_accept | cmd_reject;

  always_comb begin
    for (int w = 0; w < RSA_MOD_REGS; w++) begin
      hwif_in.RSA_MODULUS[w].MODULUS.hwclr = zeroize_reg;
    end
    for (int w = 0; w < RSA_A_REGS; w++) begin
      hwif_in.RSA_A[w].A.hwclr = zeroize_reg;
    end
    for (int w = 0; w < RSA_B_REGS; w++) begin
      hwif_in.RSA_B[w].B.hwclr = zeroize_reg;
    end
    for (int w = 0; w < RSA_E_REGS; w++) begin
      hwif_in.RSA_E[w].E.hwclr = zeroize_reg;
    end
    for (int w = 0; w < RSA_D_REGS; w++) begin
      hwif_in.RSA_D[w].D.hwclr = zeroize_reg;
    end
    // Clear all CRT key registers regardless of build-time write gating.
    for (int w = 0; w < RSA_P_REGS; w++) begin
      hwif_in.RSA_P[w].P.hwclr = zeroize_reg;
    end
    for (int w = 0; w < RSA_Q_REGS; w++) begin
      hwif_in.RSA_Q[w].Q.hwclr = zeroize_reg;
    end
    for (int w = 0; w < RSA_DP_REGS; w++) begin
      hwif_in.RSA_DP[w].DP.hwclr = zeroize_reg;
    end
    for (int w = 0; w < RSA_DQ_REGS; w++) begin
      hwif_in.RSA_DQ[w].DQ.hwclr = zeroize_reg;
    end
    for (int w = 0; w < RSA_QINV_REGS; w++) begin
      hwif_in.RSA_QINV[w].QINV.hwclr = zeroize_reg;
    end
  end

  // RESULT is written from the high indices down, matching the operand
  // convention: register word 0 is the most significant.
  always_comb begin
    for (int w = 0; w < RSA_RES_REGS; w++) begin
      hwif_in.RSA_RESULT[w].RESULT.we    = 1'b0;
      hwif_in.RSA_RESULT[w].RESULT.next  = 32'h0;
      hwif_in.RSA_RESULT[w].RESULT.hwclr = zeroize_reg;
    end
    for (int w = 0; w < KEY_WORDS; w++) begin
      hwif_in.RSA_RESULT[RSA_RES_REGS-KEY_WORDS+w].RESULT.we   = result_we & ~zeroize_reg;
      hwif_in.RSA_RESULT[RSA_RES_REGS-KEY_WORDS+w].RESULT.next = result_reg[(KEY_WORDS-1-w)*32 +: 32];
    end
  end

  // PRODUCT is 2*KEY_SIZE bits and follows the same convention: the product
  // occupies the low (least significant) end of the 8192-bit aperture.
  always_comb begin
    for (int w = 0; w < RSA_PROD_REGS; w++) begin
      hwif_in.RSA_PRODUCT[w].PRODUCT.we    = 1'b0;
      hwif_in.RSA_PRODUCT[w].PRODUCT.next  = 32'h0;
      hwif_in.RSA_PRODUCT[w].PRODUCT.hwclr = zeroize_reg;
    end
    for (int w = 0; w < 2*KEY_WORDS; w++) begin
      hwif_in.RSA_PRODUCT[RSA_PROD_REGS-2*KEY_WORDS+w].PRODUCT.we   = product_we & ~zeroize_reg;
      hwif_in.RSA_PRODUCT[RSA_PROD_REGS-2*KEY_WORDS+w].PRODUCT.next = product_reg[(2*KEY_WORDS-1-w)*32 +: 32];
    end
  end

  always_comb hwif_in.intr_block_rf.notif_internal_intr_r.notif_cmd_done_sts.hwset    = done_pulse;
  always_comb hwif_in.intr_block_rf.error_internal_intr_r.error_internal_sts.hwset    = error_pulse;

  always_comb error_intr = hwif_out.intr_block_rf.error_global_intr_r.intr;
  always_comb notif_intr = hwif_out.intr_block_rf.notif_global_intr_r.intr;

endmodule
