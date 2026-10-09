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
// tessera_rsa_mont_const
//
// Derives the ladder's Montgomery constants from the supplied modulus:
//
//   n_prime_lsw = (-n^-1) mod 2^RADIX
//   r_pow_1     = R   mod n
//   r_pow_2     = R^2 mod n        with R = 2^(RADIX * S_NUM)
//
// S_NUM includes one extra word beyond the modulus.  Derive trusted reduction
// constants internally rather than exposing firmware-writable context registers.
// CRT contexts contain secret-prime-derived values and must be zeroized.
//
// Algorithm
// ---------
// n_prime uses Newton iteration x <- x*(2-n*x) modulo 2^RADIX.
// For odd n, seed x=n is correct to 3 bits; five two-cycle rounds cover
// radices through 96, using one RADIX-bit multiplier per lane.
//
// Seed acc=2^floor(log2(n)), strictly below odd n>2, then modular-double to
// R mod n.  Each doubling advances RSA_MC_SWEEP_WORDS words per cycle using
// one grouped subtract, avoiding a ripple of narrow subtractors.
//
// For R^2, write x_s = 2^(F+s) mod n, where F=FULL_REG_SIZE:
//
//     MM(x_s, x_t) = 2^(F+s) * 2^(F+t) * 2^-F = x_(s+t)     (F = FULL_REG_SIZE)
//     double(x_s)  =                            x_(s+1)
//
// From x_0, take S_NUM doublings followed by log2(RADIX) squarings:
// S_NUM*RADIX=F.  Grouping all squarings permits one forwarded run costing
// 3*S_NUM+(k-1)*MM_II, rather than paying full latency at every interruption.
// This uniform schedule avoids geometry-specific chain state; it need not be
// globally optimal for every geometry.
//
// Borrow tessera_rsa_modexp through mm_req/mm_done.  LDMOD and MODEXP are mutually
// exclusive in tessera_rsa_ctrl, so no array arbitration is needed.
//
// Seeded latency depends on the modulus MSB.  For secret CRT primes, tessera_rsa_ctrl
// enforces the public lane width and top bit, fixing both seeds.  Carry/borrow
// selects do not change the schedule.  The caller must validate odd n>2.


module tessera_rsa_mont_const
  import tessera_rsa_params_pkg::*;
#(
    parameter int unsigned MODULUS_BIT_WIDTH = RSA_KEY_SIZE,
    parameter int unsigned WORD_BIT_WIDTH    = RSA_RADIX,
    parameter int unsigned FULL_REG_SIZE     = RSA_FULL_REG_SIZE,
    // Build the second lane only for CRT.
    parameter bit          DUAL_EN           = 1'b0
) (
    input  wire                                 clk,
    input  wire                                 rst_n,
    input  wire                                 zeroize,

    input  wire                                 start_in,
    input  wire [MODULUS_BIT_WIDTH-1:0]         n_in,

    // Sampled with start_in.  Use R_half=2^(RADIX*S_NUM_H); n occupies the low
    // NWORDS_H words of the full-width port, with upper words zero.
    input  wire                                 half_i,

    // Top stage modulus_width/(2*RADIX), sampled on start; zero uses half_i.
    // The resulting word count must divide into whole SWPC-word groups.
    input  wire [7:0]                           geom_i,

    // ----------------------------------------------------------------------
    // Dual mode is sampled on start and implies half mode.  Lane 1 uses the
    // accumulator's upper half; both moduli arrive right-aligned on their ports.
    // One schedule drives both lanes, seeded at the lower modulus MSB.
    // ----------------------------------------------------------------------
    input  wire                                 dual_i,
    input  wire [MODULUS_BIT_WIDTH-1:0]         n1_in,

    output logic [WORD_BIT_WIDTH-1:0]           n_prime_lsw_out,
    output logic [MODULUS_BIT_WIDTH-1:0]        r_pow_1_mod_n_out,
    output logic [MODULUS_BIT_WIDTH-1:0]        r_pow_2_mod_n_out,
    // Lane 1 constants.  Constant zero unless DUAL_EN.
    output logic [WORD_BIT_WIDTH-1:0]           n_prime1_lsw_out,
    output logic [MODULUS_BIT_WIDTH-1:0]        r_pow_1_mod_n1_out,
    output logic [MODULUS_BIT_WIDTH-1:0]        r_pow_2_mod_n1_out,

    // Borrowed MM service: pulse mm_req_out; return the requested squaring-run
    // result under the same context with mm_done_in.
    output logic                                mm_req_out,
    // Service geometry must use the same R as the context being derived.
    output logic                                mm_half_out,
    // Explicit geometry for the shared multiplier.
    output logic [7:0]                          mm_geom_out,
    // Additional forwarded squarings after the first; zero means one MM.
    output logic [5:0]                          mm_sq_rep_out,
    // Hold routing through request and wait: internal relaunches resample
    // modulus, half and dual selects.
    output logic                                mm_hold_out,
    output logic [MODULUS_BIT_WIDTH-1:0]        mm_a_out,
    output logic [MODULUS_BIT_WIDTH-1:0]        mm_b_out,
    input  wire                                 mm_done_in,
    input  wire  [MODULUS_BIT_WIDTH-1:0]        mm_result_in,
    // Dual service runs both contexts under the same squaring schedule.
    output logic                                mm_dual_out,
    output logic [MODULUS_BIT_WIDTH-1:0]        mm_a1_out,
    output logic [MODULUS_BIT_WIDTH-1:0]        mm_b1_out,
    input  wire  [MODULUS_BIT_WIDTH-1:0]        mm_result1_in,

    output logic                                done_out,
    output logic                                busy_out
);

  localparam int unsigned NWORDS    = MODULUS_BIT_WIDTH / WORD_BIT_WIDTH;
  localparam int unsigned WIDX_W    = $clog2(NWORDS);
  // Grouped sweep geometry; SWPC=1 is word-serial.
  localparam int unsigned SWPC      = RSA_MC_SWEEP_WORDS;
  localparam int unsigned GRP_W     = SWPC * WORD_BIT_WIDTH;
  localparam int unsigned NGRP      = NWORDS / SWPC;
  // Runtime group count uses a shift, requiring power-of-two SWPC.
  localparam int unsigned SWPC_LOG2 = $clog2(SWPC);
  localparam int unsigned GIDX_W    = (NGRP > 1) ? $clog2(NGRP) : 1;
  // Width of a bit index within one word.
  localparam int unsigned BIDX_W    = $clog2(WORD_BIT_WIDTH);
  // Sweep through R mod n and S_NUM more doublings to x_S_NUM.
  // Reserve a spare count so the terminal increment cannot wrap.
  localparam int unsigned S_NUM     = NWORDS + 1;
  localparam int unsigned NDBL      = FULL_REG_SIZE + S_NUM + 1;
  localparam int unsigned DIDX_W    = $clog2(NDBL + 1);
  localparam int unsigned NPRIME_IT = 5;

  // S_NUM*2^SQ_RUN = S_NUM*RADIX = FULL_REG_SIZE, also for half geometry.
  localparam int unsigned SQ_RUN    = $clog2(WORD_BIT_WIDTH);

  // Array tiling requires odd S_NUM; full and half satisfy S_NUM=2*S_NUM_H-1.
  localparam int unsigned NWORDS_H          = NWORDS / 2;
  localparam int unsigned NGRP_H            = NWORDS_H / SWPC;
  localparam int unsigned S_NUM_H           = NWORDS_H + 1;
  localparam int unsigned FULL_REG_SIZE_H   = S_NUM_H * WORD_BIT_WIDTH;

  typedef logic [WORD_BIT_WIDTH-1:0] word_t;

  typedef enum logic [2:0] {
    IDLE_ST,
    NPRIME_ST,
    DOUBLE_ST,
    SELECT_ST,
    MM_REQ_ST,
    MM_WAIT_ST,
    DONE_ST
  } state_e;

  state_e                       state, state_next;

  logic                         chain_fin;  // the squaring run has retired

  word_t  [NWORDS-1:0]          n_words;
  // Store both candidates; select lazily on the next read to keep each
  // doubling at one group sweep.
  word_t  [NWORDS-1:0]          dbl_words;
  word_t  [NWORDS-1:0]          sub_words;
  word_t  [NWORDS-1:0]          r1_words;
  logic                         use_sub;

  logic [GIDX_W-1:0]            gidx;
  logic                         gidx_last;
  logic [DIDX_W-1:0]            didx;

  logic                         shift_carry;
  logic                         borrow;

  // Lanes share control; only value-dependent carry, borrow and select differ.
  logic                         use_sub1;
  logic                         shift_carry1;
  logic                         borrow1;
  // Raised for the whole derivation.  A literal 0 when DUAL_EN is 0.
  logic                         dual_reg;
  logic                         dual;
  assign dual = DUAL_EN & dual_reg;

  // n_prime datapath
  logic [$clog2(2*NPRIME_IT+1)-1:0] np_cnt;
  word_t                        np_x;
  word_t                        np_t;
  word_t                        np_mul_a;
  word_t                        np_mul_b;
  word_t                        np_prod;

  // Lane 1 Newton uses a second multiplier with the same fixed round count.
  word_t                        np_x1;
  word_t                        np_t1;
  word_t                        np_mul_a1;
  word_t                        np_mul_b1;
  word_t                        np_prod1;

  // Capture width at start so it cannot change during derivation.
  logic                     half_reg;   // dual_i implies this
  // Where the accumulator holds R mod n, which is captured on the way past.
  logic [DIDX_W-1:0]        f_target;
  // The terminal step advances didx to dbl_target+1, leaving x_S_NUM for
  // SQ_RUN squarings to reach x_F.
  logic [DIDX_W-1:0]        dbl_target;

  // Captured geometry: nwords=2*TS, s_num=nwords+1, F=s_num*RADIX,
  // groups=nwords/SWPC.  Zero uses the captured half-mode selection.
  logic [7:0]               geom_reg;
  logic [WIDX_W:0]          nwords_cur;
  logic [WIDX_W+1:0]        s_num_cur;
  assign nwords_cur = (geom_reg != 8'd0) ? (WIDX_W+1)'({geom_reg, 1'b0})
                                         : (half_reg ? (WIDX_W+1)'(NWORDS_H)
                                                     : (WIDX_W+1)'(NWORDS));
  assign s_num_cur  = (WIDX_W+2)'(nwords_cur) + (WIDX_W+2)'(1);

  always_comb begin
    f_target   = DIDX_W'(s_num_cur) << BIDX_W;
    dbl_target = f_target + DIDX_W'(s_num_cur) - DIDX_W'(1);
  end

  // Sweep only active groups: reduced accumulators fit the captured width.
  logic [GIDX_W-1:0]            gidx_top;
  assign gidx_top  = GIDX_W'((nwords_cur >> SWPC_LOG2) - (WIDX_W+1)'(1));

  // Explicit geometry sets lane width; legacy dual mode always uses NWORDS_H.
  logic [WIDX_W:0]          nwords_lane_cur;
  assign nwords_lane_cur = (geom_reg != 8'd0) ? (WIDX_W+1)'({geom_reg, 1'b0})
                                              : (WIDX_W+1)'(NWORDS_H);
  assign gidx_last = (gidx == gidx_top);

  // ---------------------------------------------------------------------
  // Seed for the first doubling sweep
  //
  // Seed 2^(msw*WORD_BIT_WIDTH+msb), using the top set bit within the top word.
  // It is strictly below odd n>=3: equality would make n a power of two.
  // Bit-level seeding skips up to WORD_BIT_WIDTH-1 extra doublings.
  // ---------------------------------------------------------------------
  // Dual lanes share didx, so seed both at the lower MSB to stay reduced under
  // both moduli.  Equal normalized prime widths give equal, fixed seeds;
  // otherwise seed-dependent extra doublings affect latency.
  logic [WIDX_W-1:0]        seed_msw0, seed_msw1, seed_msw;
  word_t                    seed_word0, seed_word1;
  logic [BIDX_W-1:0]        seed_bit0, seed_bit1, seed_bit;
  logic [DIDX_W-1:0]        seed_didx0, seed_didx1;
  word_t [NWORDS-1:0]       seed_acc;
  logic [DIDX_W-1:0]        seed_didx;

  always_comb begin
    seed_msw0 = '0;
    seed_msw1 = '0;
    for (int w = 0; w < NWORDS; w++) begin
      if (n_in [w*WORD_BIT_WIDTH +: WORD_BIT_WIDTH] != '0) seed_msw0 = WIDX_W'(w);
      if (n1_in[w*WORD_BIT_WIDTH +: WORD_BIT_WIDTH] != '0) seed_msw1 = WIDX_W'(w);
    end
  end

  // Equality mux avoids out-of-bounds variable-index warnings (VCS SIOB).
  always_comb begin
    seed_word0 = '0;
    seed_word1 = '0;
    for (int w = 0; w < NWORDS; w++) begin
      if (WIDX_W'(w) == seed_msw0) seed_word0 = n_in [w*WORD_BIT_WIDTH +: WORD_BIT_WIDTH];
      if (WIDX_W'(w) == seed_msw1) seed_word1 = n1_in[w*WORD_BIT_WIDTH +: WORD_BIT_WIDTH];
    end
  end

  always_comb begin
    seed_bit0 = '0;
    seed_bit1 = '0;
    for (int b = 0; b < WORD_BIT_WIDTH; b++) begin
      if (seed_word0[b]) seed_bit0 = BIDX_W'(b);
      if (seed_word1[b]) seed_bit1 = BIDX_W'(b);
    end
  end

  always_comb begin
    seed_didx0 = (DIDX_W'(seed_msw0) * DIDX_W'(WORD_BIT_WIDTH)) + DIDX_W'(seed_bit0);
    seed_didx1 = (DIDX_W'(seed_msw1) * DIDX_W'(WORD_BIT_WIDTH)) + DIDX_W'(seed_bit1);
  end

  // Use the lower seed in dual mode, otherwise lane 0.
  always_comb begin
    if ((DUAL_EN & dual_i) && (seed_didx1 < seed_didx0)) begin
      seed_msw  = seed_msw1;
      seed_bit  = seed_bit1;
      seed_didx = seed_didx1;
    end else begin
      seed_msw  = seed_msw0;
      seed_bit  = seed_bit0;
      seed_didx = seed_didx0;
    end
  end

  // Lane 0 takes accumulator word seed_msw; lane 1 takes the same bit position
  // NWORDS_H words higher, which is where its datapath lives.
  always_comb begin
    seed_acc = '0;
    for (int w = 0; w < NWORDS; w++) begin
      if (WIDX_W'(w) == seed_msw)
        seed_acc[w] = word_t'(1) << seed_bit;
      if ((DUAL_EN & dual_i) && (WIDX_W'(w) == WIDX_W'(NWORDS_H) + seed_msw))
        seed_acc[w] = word_t'(1) << seed_bit;
    end
  end

  // ---------------------------------------------------------------------
  // Current accumulator group, resolved through the pending select
  // ---------------------------------------------------------------------
  // Equality selection avoids out-of-bounds variable-index warnings.
  logic [GRP_W-1:0] grp_acc;
  logic [GRP_W-1:0] grp_n;
  // Lane 1 uses the same group index in the accumulator's upper half.
  logic [GRP_W-1:0] grp_acc1;
  logic [GRP_W-1:0] grp_n1;
  logic [GIDX_W-1:0] gidx1;
  assign gidx1 = gidx + GIDX_W'(NGRP_H);

  always_comb begin
    grp_acc  = '0;
    grp_n    = '0;
    grp_acc1 = '0;
    grp_n1   = '0;
    for (int g = 0; g < NGRP; g++) begin
      if (GIDX_W'(g) == gidx) begin
        for (int k = 0; k < SWPC; k++) begin
          grp_acc[k*WORD_BIT_WIDTH +: WORD_BIT_WIDTH] =
              use_sub ? sub_words[g*SWPC + k] : dbl_words[g*SWPC + k];
          grp_n  [k*WORD_BIT_WIDTH +: WORD_BIT_WIDTH] = n_words[g*SWPC + k];
        end
      end
      if (DUAL_EN && (GIDX_W'(g) == gidx1)) begin
        for (int k = 0; k < SWPC; k++) begin
          grp_acc1[k*WORD_BIT_WIDTH +: WORD_BIT_WIDTH] =
              use_sub1 ? sub_words[g*SWPC + k] : dbl_words[g*SWPC + k];
          grp_n1  [k*WORD_BIT_WIDTH +: WORD_BIT_WIDTH] = n_words[g*SWPC + k];
        end
      end
    end
  end

  // ---------------------------------------------------------------------
  // Doubling step, SWPC words per cycle
  //
  // One wide subtract permits parallel-prefix synthesis; shift_carry and
  // borrow link successive groups.
  // ---------------------------------------------------------------------
  logic [GRP_W-1:0] grp_shift;
  logic [GRP_W-1:0] grp_sub;
  logic [GRP_W:0]   grp_sub_full;
  logic             grp_carry_out;
  logic [GRP_W-1:0] grp_shift1;
  logic [GRP_W-1:0] grp_sub1;
  logic [GRP_W:0]   grp_sub_full1;
  logic             grp_carry_out1;

  always_comb begin
    grp_shift     = {grp_acc[GRP_W-2:0], shift_carry};
    grp_carry_out = grp_acc[GRP_W-1];
    grp_sub_full  = {1'b0, grp_shift} - {1'b0, grp_n} - {{GRP_W{1'b0}}, borrow};
    grp_sub       = grp_sub_full[GRP_W-1:0];

    grp_shift1     = {grp_acc1[GRP_W-2:0], shift_carry1};
    grp_carry_out1 = grp_acc1[GRP_W-1];
    grp_sub_full1  = {1'b0, grp_shift1} - {1'b0, grp_n1} - {{GRP_W{1'b0}}, borrow1};
    grp_sub1       = grp_sub_full1[GRP_W-1:0];
  end

  // ---------------------------------------------------------------------
  // n_prime Newton iteration: x <- x * (2 - n*x)  (mod 2^WORD_BIT_WIDTH)
  // ---------------------------------------------------------------------
  always_comb begin
    if (np_cnt[0]) begin
      np_mul_a = np_x;
      np_mul_b = np_t;
    end else begin
      np_mul_a = n_words[0];
      np_mul_b = np_x;
    end
  end
  always_comb np_prod = np_mul_a * np_mul_b;

  // Lane 1, same iteration against n1's least significant word.
  always_comb begin
    if (np_cnt[0]) begin
      np_mul_a1 = np_x1;
      np_mul_b1 = np_t1;
    end else begin
      np_mul_a1 = n_words[NWORDS_H];
      np_mul_b1 = np_x1;
    end
  end
  always_comb np_prod1 = np_mul_a1 * np_mul_b1;

  // ---------------------------------------------------------------------
  // Control
  // ---------------------------------------------------------------------
  always_comb begin
    state_next = state;
    unique case (state)
      IDLE_ST   : state_next = start_in ? NPRIME_ST : IDLE_ST;
      NPRIME_ST : state_next = (np_cnt == ($clog2(2*NPRIME_IT+1))'(2*NPRIME_IT)) ? DOUBLE_ST : NPRIME_ST;
      // Finish the doubling prefix at x_S_NUM.
      DOUBLE_ST : state_next = (gidx_last && (didx == dbl_target)) ? SELECT_ST : DOUBLE_ST;
      // Resolve the lazy select before MM operand or final-result reads.
      SELECT_ST : state_next = chain_fin ? DONE_ST : MM_REQ_ST;
      MM_REQ_ST : state_next = MM_WAIT_ST;
      MM_WAIT_ST: state_next = mm_done_in ? SELECT_ST : MM_WAIT_ST;
      DONE_ST   : state_next = IDLE_ST;
      default   : state_next = IDLE_ST;
    endcase
  end

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      state           <= IDLE_ST;
      n_words         <= '0;
      dbl_words       <= '0;
      sub_words       <= '0;
      r1_words        <= '0;
      use_sub         <= 1'b0;
      gidx            <= '0;
      didx            <= '0;
      shift_carry     <= 1'b0;
      borrow          <= 1'b0;
      use_sub1        <= 1'b0;
      shift_carry1    <= 1'b0;
      borrow1         <= 1'b0;
      dual_reg        <= 1'b0;
      np_cnt          <= '0;
      np_x            <= '0;
      np_t            <= '0;
      np_x1           <= '0;
      np_t1           <= '0;
      chain_fin       <= 1'b0;
      half_reg        <= 1'b0;
      geom_reg        <= 8'd0;
      n_prime_lsw_out <= '0;
      n_prime1_lsw_out<= '0;
    end else if (zeroize) begin
      state           <= IDLE_ST;
      n_words         <= '0;
      dbl_words       <= '0;
      sub_words       <= '0;
      r1_words        <= '0;
      use_sub         <= 1'b0;
      gidx            <= '0;
      didx            <= '0;
      shift_carry     <= 1'b0;
      borrow          <= 1'b0;
      use_sub1        <= 1'b0;
      shift_carry1    <= 1'b0;
      borrow1         <= 1'b0;
      dual_reg        <= 1'b0;
      np_cnt          <= '0;
      np_x            <= '0;
      np_t            <= '0;
      np_x1           <= '0;
      np_t1           <= '0;
      chain_fin       <= 1'b0;
      half_reg        <= 1'b0;
      geom_reg        <= 8'd0;
      n_prime_lsw_out <= '0;
      n_prime1_lsw_out<= '0;
    end else begin
      state <= state_next;

      unique case (state)
        IDLE_ST: begin
          if (start_in) begin
            // Dual mode packs p/q in the low/high halves; single mode uses n_in.
            n_words <= (DUAL_EN & dual_i)
                     ? { n1_in[MODULUS_BIT_WIDTH/2-1:0], n_in[MODULUS_BIT_WIDTH/2-1:0] }
                     : n_in;
            // Seed the dbl bank and its matching absolute exponent.
            dbl_words   <= seed_acc;
            sub_words   <= '0;
            use_sub     <= 1'b0;
            gidx        <= '0;
            didx        <= seed_didx;
            shift_carry <= 1'b0;
            borrow      <= 1'b0;
            use_sub1     <= 1'b0;
            shift_carry1 <= 1'b0;
            borrow1      <= 1'b0;
            dual_reg     <= dual_i;
            np_x        <= n_in[WORD_BIT_WIDTH-1:0];
            np_x1       <= n1_in[WORD_BIT_WIDTH-1:0];
            np_cnt      <= '0;
            chain_fin   <= 1'b0;
            // Dual placement requires half-width lanes.
            half_reg    <= half_i | (DUAL_EN & dual_i);
            geom_reg    <= geom_i;
          end
        end

        NPRIME_ST: begin
          np_cnt <= np_cnt + 1'b1;
          if (np_cnt[0]) begin
            np_x  <= np_prod;                      // x <- x * (2 - n*x)
            np_x1 <= np_prod1;
          end else begin
            np_t  <= word_t'(2) - np_prod;         // t <- 2 - n*x
            np_t1 <= word_t'(2) - np_prod1;
          end
          if (np_cnt == ($clog2(2*NPRIME_IT+1))'(2*NPRIME_IT)) begin
            // n_prime = -x  (mod 2^WORD_BIT_WIDTH)
            n_prime_lsw_out  <= word_t'(0) - np_x;
            n_prime1_lsw_out <= word_t'(0) - np_x1;
          end
        end

        DOUBLE_ST: begin
          for (int g = 0; g < NGRP; g++) begin
            if (GIDX_W'(g) == gidx) begin
              for (int k = 0; k < SWPC; k++) begin
                dbl_words[g*SWPC + k] <= grp_shift[k*WORD_BIT_WIDTH +: WORD_BIT_WIDTH];
                sub_words[g*SWPC + k] <= grp_sub  [k*WORD_BIT_WIDTH +: WORD_BIT_WIDTH];
              end
            end
            if (dual && (GIDX_W'(g) == gidx1)) begin
              for (int k = 0; k < SWPC; k++) begin
                dbl_words[g*SWPC + k] <= grp_shift1[k*WORD_BIT_WIDTH +: WORD_BIT_WIDTH];
                sub_words[g*SWPC + k] <= grp_sub1  [k*WORD_BIT_WIDTH +: WORD_BIT_WIDTH];
              end
            end
          end
          shift_carry     <= grp_carry_out;
          borrow          <= grp_sub_full[GRP_W];
          shift_carry1    <= grp_carry_out1;
          borrow1         <= grp_sub_full1[GRP_W];

          if (gidx_last) begin
            gidx  <= '0;
            didx  <= didx + 1'b1;
            // Since acc<n, 2*acc<2n: one subtract suffices.  Select it on
            // overflow or no borrow from the grouped subtraction.
            use_sub     <= grp_carry_out | ~grp_sub_full[GRP_W];
            shift_carry <= 1'b0;
            borrow      <= 1'b0;
            // Lane 1 selects independently without changing the schedule.
            use_sub1     <= grp_carry_out1 | ~grp_sub_full1[GRP_W];
            shift_carry1 <= 1'b0;
            borrow1      <= 1'b0;
            // Capture R mod n before the remaining doubling prefix.
            if ((state == DOUBLE_ST) && (didx == (f_target - DIDX_W'(1)))) begin
              // Bypass the active top group's result, not its old register value.
              for (int g = 0; g < NGRP; g++) begin
                for (int k = 0; k < SWPC; k++) begin
                  if (dual && (GIDX_W'(g) >= GIDX_W'(NGRP_H)))
                    r1_words[g*SWPC + k] <= (grp_carry_out1 | ~grp_sub_full1[GRP_W]) ?
                        ((GIDX_W'(g) == gidx1) ? grp_sub1  [k*WORD_BIT_WIDTH +: WORD_BIT_WIDTH]
                                               : sub_words[g*SWPC + k]) :
                        ((GIDX_W'(g) == gidx1) ? grp_shift1[k*WORD_BIT_WIDTH +: WORD_BIT_WIDTH]
                                               : dbl_words[g*SWPC + k]);
                  else
                    r1_words[g*SWPC + k] <= (grp_carry_out | ~grp_sub_full[GRP_W]) ?
                        ((GIDX_W'(g) == gidx) ? grp_sub  [k*WORD_BIT_WIDTH +: WORD_BIT_WIDTH]
                                              : sub_words[g*SWPC + k]) :
                        ((GIDX_W'(g) == gidx) ? grp_shift[k*WORD_BIT_WIDTH +: WORD_BIT_WIDTH]
                                              : dbl_words[g*SWPC + k]);
                end
              end
            end
          end else begin
            gidx <= gidx + 1'b1;
          end
        end

        MM_WAIT_ST: begin
          if (mm_done_in) begin
            // The squaring run returns a reduced result; no lazy select remains.
            dbl_words <= dual
                       ? { mm_result1_in[MODULUS_BIT_WIDTH/2-1:0],
                           mm_result_in [MODULUS_BIT_WIDTH/2-1:0] }
                       : mm_result_in;
            use_sub   <= 1'b0;
            use_sub1  <= 1'b0;
            // The complete run reaches s=F.
            chain_fin <= 1'b1;
          end
        end

        SELECT_ST: begin
          // Resolve each lane's pending select into the output bank.
          for (int g = 0; g < NGRP; g++) begin
            for (int k = 0; k < SWPC; k++) begin
              if (dual && (GIDX_W'(g) >= GIDX_W'(NGRP_H))) begin
                if (use_sub1) dbl_words[g*SWPC + k] <= sub_words[g*SWPC + k];
              end else begin
                if (use_sub)  dbl_words[g*SWPC + k] <= sub_words[g*SWPC + k];
              end
            end
          end
          use_sub  <= 1'b0;
          use_sub1 <= 1'b0;
        end

        // Every other state leaves the accumulator alone.  An empty
        // BLOCK, not an empty statement: lint W193.
        default: begin end
      endcase
    end
  end

  always_comb begin
    // In dual mode, mask each output to its own lane aperture.
    r_pow_1_mod_n_out = r1_words;
    r_pow_2_mod_n_out = dbl_words;
    // Mask at runtime lane width to exclude inactive or stale upper words.
    if (dual) begin
      for (int w = 0; w < NWORDS; w++) begin
        if ((WIDX_W+1)'(w) >= nwords_lane_cur) begin
          r_pow_1_mod_n_out[w*WORD_BIT_WIDTH +: WORD_BIT_WIDTH] = '0;
          r_pow_2_mod_n_out[w*WORD_BIT_WIDTH +: WORD_BIT_WIDTH] = '0;
        end
      end
    end
    done_out          = (state == DONE_ST);
    busy_out          = (state != IDLE_ST);
    // SELECT_ST resolved the accumulator; the service request only squares.
    mm_req_out        = (state == MM_REQ_ST);
    mm_a_out          = dbl_words;
    mm_b_out          = dbl_words;
    mm_half_out       = half_reg;
    mm_geom_out       = geom_reg;
    mm_sq_rep_out     = 6'(SQ_RUN - 1);
    mm_hold_out       = (state == MM_REQ_ST) || (state == MM_WAIT_ST);

    // Lane 1 lives in the upper half of the accumulator; every consumer wants
    // it right justified in its own full-width aperture.
    mm_dual_out         = dual;
    mm_a1_out           = '0;
    mm_b1_out           = '0;
    r_pow_1_mod_n1_out  = '0;
    r_pow_2_mod_n1_out  = '0;
    // Gather packed word_t arrays wordwise to avoid VCS SIOB warnings.
    if (DUAL_EN) begin
      // Exclude words above lane 1's runtime width.
      for (int w = 0; w < NWORDS_H; w++) begin
        if ((WIDX_W+1)'(w) < nwords_lane_cur) begin
          mm_a1_out         [w*WORD_BIT_WIDTH +: WORD_BIT_WIDTH] = dbl_words[NWORDS_H + w];
          mm_b1_out         [w*WORD_BIT_WIDTH +: WORD_BIT_WIDTH] = dbl_words[NWORDS_H + w];
          r_pow_1_mod_n1_out[w*WORD_BIT_WIDTH +: WORD_BIT_WIDTH] = r1_words [NWORDS_H + w];
          r_pow_2_mod_n1_out[w*WORD_BIT_WIDTH +: WORD_BIT_WIDTH] = dbl_words[NWORDS_H + w];
        end
      end
    end
  end

  // Odd n>2 is required for both the inverse and the strictly reduced seed.
  //synopsys translate_off
  always_ff @(posedge clk) begin
    if (rst_n && !zeroize && start_in && (state == IDLE_ST)) begin
      if (!n_in[0] || (n_in <= MODULUS_BIT_WIDTH'(2)))
        $error("tessera_rsa_mont_const: modulus must be odd and greater than 2");
      // Dual moduli have the same arithmetic requirements and must fit each lane.
      if (dual_i) begin
        if (!n1_in[0] || (n1_in <= MODULUS_BIT_WIDTH'(2)))
          $error("tessera_rsa_mont_const: dual_i requires n1_in odd and greater than 2");
        if (|n1_in[MODULUS_BIT_WIDTH-1 : MODULUS_BIT_WIDTH/2])
          $error("tessera_rsa_mont_const: dual_i requires n1_in to be half width");
        if (|n_in[MODULUS_BIT_WIDTH-1 : MODULUS_BIT_WIDTH/2])
          $error("tessera_rsa_mont_const: dual_i requires n_in to be half width");
      end
    end
  end

  //synopsys translate_on

  // Keep build-time checks visible to synthesis; the runtime assertions above
  // are simulation-only.  The chain requires F=S_NUM*2**SQ_RUN and power-of-two
  // RADIX in both full and half geometry.
  if ((2 ** SQ_RUN) != WORD_BIT_WIDTH)
    $fatal(1, "tessera_rsa_mont_const: RADIX (%0d) must be a power of two.", WORD_BIT_WIDTH);
  if ((S_NUM * (2 ** SQ_RUN)) != FULL_REG_SIZE)
    $fatal(1, "tessera_rsa_mont_const: S_NUM*2**SQ_RUN (%0d) != FULL_REG_SIZE (%0d).",
           S_NUM * (2 ** SQ_RUN), FULL_REG_SIZE);
  if ((S_NUM_H * (2 ** SQ_RUN)) != FULL_REG_SIZE_H)
    $fatal(1, "tessera_rsa_mont_const: S_NUM_H*2**SQ_RUN (%0d) != FULL_REG_SIZE_H (%0d).",
           S_NUM_H * (2 ** SQ_RUN), FULL_REG_SIZE_H);
  // mm_sq_rep_out is 6 bits.
  if (SQ_RUN < 1 || SQ_RUN > 64)
    $fatal(1, "tessera_rsa_mont_const: SQ_RUN (%0d) is out of range.", SQ_RUN);
  // Half geometry must split evenly and leave room below R_half for the seed.
  if ((NWORDS % 2) != 0)
    $fatal(1, "tessera_rsa_mont_const: NWORDS (%0d) must be even for the half-width context.", NWORDS);
  if (((NWORDS_H - 1) * WORD_BIT_WIDTH) >= FULL_REG_SIZE_H)
    $fatal(1, "tessera_rsa_mont_const: half seed exponent (%0d) is not below FULL_REG_SIZE_H (%0d).",
           (NWORDS_H - 1) * WORD_BIT_WIDTH, FULL_REG_SIZE_H);
  // Full and half sweeps must end on group boundaries.
  if ((SWPC == 0) || ((NWORDS % SWPC) != 0))
    $fatal(1, "tessera_rsa_mont_const: RSA_MC_SWEEP_WORDS (%0d) must divide NWORDS (%0d).", SWPC, NWORDS);
  if ((NWORDS_H % SWPC) != 0)
    $fatal(1, "tessera_rsa_mont_const: RSA_MC_SWEEP_WORDS (%0d) must divide NWORDS_H (%0d).", SWPC, NWORDS_H);

  // The runtime geometry turns NWORDS/SWPC into a shift, so SWPC must be a
  // power of two as well as a divisor.
  if ((SWPC & (SWPC - 1)) != 0)
    $fatal(1, "tessera_rsa_mont_const: RSA_MC_SWEEP_WORDS (%0d) must be a power of two.", SWPC);
endmodule
