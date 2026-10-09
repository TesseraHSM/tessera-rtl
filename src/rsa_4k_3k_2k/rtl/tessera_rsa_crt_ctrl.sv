// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//======================================================================
//
// tessera_rsa_crt_ctrl.sv
// ---------------
// CRT sequencing, p/q contexts, Garner recombination and Bellcore verification.
// tessera_rsa_ctrl instantiates this only when CRT is built, tying off its controls
// otherwise.  The ladder, Montgomery array and constant generator are shared.
//
// LDMOD builds p-half and q-half together, then n-full.  Save p/q contexts here
// and leave n resident in tessera_rsa_mont_const for non-CRT commands and verification.
// MODEXP_SEC_CRT reduces x modulo p and q sequentially, runs both half-width
// ladders together, recombines, then verifies m^e mod n == x.
//
// Full-width base reduction must consume all KEY bits before narrowing:
//     T_p     = 2^(KEY/2) - p
//     s1      = MM_full(x,  r2_p)  = x * 2^RADIX mod p
//     x mod p = MM_half(s1, T_p)
//
// R_half=2^(KEY/2+RADIX) and T_p is congruent to 2^(KEY/2) modulo p, so the
// second MM returns an ordinary integer for the ladder's normal domain entry.
// tessera_rsa_ctrl enforces prime top bits, ensuring T_p < p and Garner's q < 2p bound.
//
// Bellcore verification is mandatory: one bad CRT branch can expose a factor
// through gcd(m^e-x,n).  Mismatch forces the result to zero and raises fault_o
// with done_o; tessera_rsa_ctrl withholds VALID.
//
// Secret ladders use exp_public_o=0 and a fixed runtime lane-width bound,
// independent of dp/dq.  Only verification uses public-e shortcuts.  The final
// full-width comparison has fixed cycle cost; the fault flag is observable.
//
//======================================================================

module tessera_rsa_crt_ctrl
  import tessera_rsa_params_pkg::*;
#(
    parameter int unsigned KEY_SIZE  = RSA_KEY_SIZE,
    parameter int unsigned RADIX     = RSA_RADIX,
    parameter int unsigned EXP_SIZE  = RSA_KEY_SIZE + 64,
    localparam int unsigned HALF_SIZE = KEY_SIZE / 2,
    localparam int unsigned EXP_IDX_W = $clog2(EXP_SIZE)
) (
    input  wire                          clk,
    input  wire                          rst_n,
    input  wire                          zeroize,

    // Full-key top stage KEYLEN/(2*RADIX); zero selects the built width.
    // Each lane uses geom_i>>1 stages, or geom_i*RADIX bits for valid geometry.
    input  wire [7:0]                    geom_i,

    // ---------------------------------------------------------------------
    // Commands from tessera_rsa_ctrl
    // ---------------------------------------------------------------------
    // Accepted LDMOD with validated CRT material; otherwise tessera_rsa_ctrl builds n only.
    input  wire                          ldmod_start_i,
    // Any accepted or rejected LDMOD that does not arm CRT invalidates old p/q
    // contexts, preventing reuse with an unrelated modulus.
    input  wire                          ctx_invalidate_i,
    // Run a CRT private exponentiation on base_i.
    input  wire                          exp_start_i,

    // ---------------------------------------------------------------------
    // Operands.  p, q, qinv, dp and dq are SECRET.
    // ---------------------------------------------------------------------
    input  wire [KEY_SIZE-1:0]           n_i,
    input  wire [KEY_SIZE-1:0]           base_i,
    input  wire [KEY_SIZE-1:0]           p_i,
    input  wire [KEY_SIZE-1:0]           q_i,
    input  wire [KEY_SIZE-1:0]           qinv_i,
    input  wire [KEY_SIZE-1:0]           dp_i,
    input  wire [KEY_SIZE-1:0]           dq_i,
    // Public exponent, for the Bellcore verification.
    input  wire [EXP_SIZE-1:0]           e_i,
    input  wire [EXP_IDX_W-1:0]          e_msb_index_i,

    // ---------------------------------------------------------------------
    // Borrowed tessera_rsa_mont_const
    // ---------------------------------------------------------------------
    output logic                         mc_start_o,
    output logic                         mc_half_o,
    output logic [KEY_SIZE-1:0]          mc_n_o,
    // Derive both prime contexts together: lane 0 is p, lane 1 is q.
    output logic                         mc_dual_o,
    output logic [KEY_SIZE-1:0]          mc_n1_o,
    input  wire                          mc_done_i,
    input  wire [RADIX-1:0]              mc_n_prime_i,
    input  wire [KEY_SIZE-1:0]           mc_r1_i,
    input  wire [KEY_SIZE-1:0]           mc_r2_i,
    input  wire [RADIX-1:0]              mc_n_prime1_i,
    input  wire [KEY_SIZE-1:0]           mc_r1_1_i,
    input  wire [KEY_SIZE-1:0]           mc_r2_1_i,

    // ---------------------------------------------------------------------
    // Borrowed tessera_rsa_modexp.  This module drives the modulus context as well as
    // the operands, because it switches between the p, q and n contexts.
    // ---------------------------------------------------------------------
    output logic                         me_start_o,
    output logic                         me_mul_mode_o,
    output logic                         me_mm_mode_o,
    output logic                         me_mm_half_o,
    output logic                         me_half_o,
    output logic                         me_exp_public_o,
    output logic [KEY_SIZE-1:0]          me_base_o,
    output logic [KEY_SIZE-1:0]          me_mul_b_o,
    output logic [EXP_SIZE-1:0]          me_exponent_o,
    output logic [EXP_IDX_W-1:0]         me_msb_index_o,
    output logic [KEY_SIZE-1:0]          me_n_o,
    output logic [RADIX-1:0]             me_n_prime_o,
    output logic [KEY_SIZE-1:0]          me_r1_o,
    output logic [KEY_SIZE-1:0]          me_r2_o,
    // Parallel p/q ladders share one schedule.  Base reductions remain
    // sequential because their first MM must consume the full-width x.
    output logic                         me_dual_o,
    output logic [KEY_SIZE-1:0]          me_base1_o,
    output logic [EXP_SIZE-1:0]          me_exponent1_o,
    output logic [KEY_SIZE-1:0]          me_n1_o,
    output logic [RADIX-1:0]             me_n_prime1_o,
    output logic [KEY_SIZE-1:0]          me_r11_o,
    output logic [KEY_SIZE-1:0]          me_r21_o,
    input  wire                          me_done_i,
    input  wire [KEY_SIZE-1:0]           me_result_i,
    input  wire [KEY_SIZE-1:0]           me_result1_i,
    input  wire [2*KEY_SIZE-1:0]         me_product_i,

    // ---------------------------------------------------------------------
    // Results
    // ---------------------------------------------------------------------
    // Shared-datapath ownership, tied low by tessera_rsa_ctrl in non-CRT builds.
    output logic                         crt_active_o,
    // Set after CRT LDMOD; tessera_rsa_ctrl rejects CRT exponentiation while clear.
    output logic                         ctx_valid_o,
    output logic [KEY_SIZE-1:0]          result_o,
    output logic                         done_o,
    // Bellcore mismatch.  Raised with done_o; result_o is zero in that case.
    output logic                         fault_o
);

  // ---------------------------------------------------------------------
  // States
  //
  // A branch-index mux keeps the p/q reduction sequences structurally identical.
  // ---------------------------------------------------------------------
  typedef enum logic [4:0] {
    IDLE_ST,
    // LDMOD: the p and q contexts together, then the n context
    LD_PQ_REQ_ST, LD_PQ_WAIT_ST,
    LD_N_REQ_ST,  LD_N_WAIT_ST,
    LD_DONE_ST,
    // Branch: reduce, then exponentiate
    BR_RED1_REQ_ST, BR_RED1_WAIT_ST, BR_RED1_GAP_ST,
    BR_RED2_REQ_ST, BR_RED2_WAIT_ST, BR_RED2_GAP_ST,
    BR_NEXT_ST,
    BR_EXP_REQ_ST,  BR_EXP_WAIT_ST, BR_EXP_GAP_ST,
    // Recombine
    GARNER_REQ_ST,  GARNER_WAIT_ST,
    // Verify
    BELL_REQ_ST,    BELL_WAIT_ST,
    CHECK_ST,
    EXP_DONE_ST
  } state_e;

  state_e state, state_next;

  // Which branch is running: 0 = p, 1 = q.
  logic                     branch;

  // Captured operands.  Read once at start so the caller may drop its drive.
  logic [KEY_SIZE-1:0]      x_reg;
  logic [KEY_SIZE-1:0]      n_reg;
  logic [HALF_SIZE-1:0]     p_reg, q_reg;
  logic [HALF_SIZE-1:0]     qinv_reg;
  logic [HALF_SIZE-1:0]     dp_reg, dq_reg;
  logic [EXP_SIZE-1:0]      e_reg;
  logic [EXP_IDX_W-1:0]     e_msb_reg;

  // Persistent half-width p/q contexts: R_h mod prime and R_h^2 mod prime
  // fit below each prime, with one RADIX-bit inverse per lane.
  logic [RADIX-1:0]         np_p,  np_q;
  logic [HALF_SIZE-1:0]     r1_p,  r1_q;
  logic [HALF_SIZE-1:0]     r2_p,  r2_q;
  logic                     ctx_valid;

  // Branch intermediates.
  logic [KEY_SIZE-1:0]      red_reg;   // x mod p / x mod q, and the branch base
  // The two reduced bases, held until the single dual ladder consumes them.
  logic [HALF_SIZE-1:0]     redp_reg, redq_reg;
  logic [KEY_SIZE-1:0]      m1_reg, m2_reg;
  logic [KEY_SIZE-1:0]      m_reg;
  logic                     fault_reg;

  // ---------------------------------------------------------------------
  // Shared branch selects preserve identical p/q reduction schedules.
  // ---------------------------------------------------------------------
  logic [HALF_SIZE-1:0]     br_mod;
  logic [RADIX-1:0]         br_nprime;
  logic [HALF_SIZE-1:0]     br_r1, br_r2;
  logic [HALF_SIZE-1:0]     br_exp;
  // T = 2^(KEY/2) - modulus.  Valid (and strictly below the modulus) exactly
  // when the modulus has its top bit set, which tessera_rsa_ctrl enforces.
  logic [HALF_SIZE-1:0]     br_t;

  // Per-lane width, runtime.  Word-granular so nothing here needs a
  // KEY_SIZE-wide variable shifter.
  localparam int unsigned HALF_WORDS_L = HALF_SIZE / RADIX;
  logic [7:0]               lane_geom;
  logic [EXP_IDX_W-1:0]     lane_bits;
  logic [HALF_SIZE-1:0]     lane_mask;
  assign lane_geom = (geom_i != 8'd0) ? (geom_i >> 1) : 8'(HALF_SIZE / (2*RADIX));
  assign lane_bits = EXP_IDX_W'({lane_geom, 1'b0}) * EXP_IDX_W'(RADIX);
  always_comb begin
    lane_mask = '0;
    for (int w = 0; w < HALF_WORDS_L; w++)
      if (EXP_IDX_W'(w) < EXP_IDX_W'({lane_geom, 1'b0}))
        lane_mask[w*RADIX +: RADIX] = {RADIX{1'b1}};
  end

  always_comb begin
    br_mod    = branch ? q_reg  : p_reg;
    br_nprime = branch ? np_q   : np_p;
    br_r1     = branch ? r1_q   : r1_p;
    br_r2     = branch ? r2_q   : r2_p;
    br_exp    = branch ? dq_reg : dp_reg;
    // (-br_mod) mod 2^lane_bits gives 2^lane_bits-br_mod without a wide shifter.
    br_t      = (HALF_SIZE'(0) - br_mod) & lane_mask;
  end

  // ---------------------------------------------------------------------
  // Garner recombination
  // ---------------------------------------------------------------------
  logic                     gn_start;
  logic                     gn_mm_req, gn_mul_req, gn_mm_half;
  logic [KEY_SIZE-1:0]      gn_mm_a, gn_mm_b;
  logic [KEY_SIZE-1:0]      gn_result;
  logic                     gn_done;
  // Included in shared-datapath ownership.
  logic                     gn_busy;

  tessera_rsa_crt_garner #(
      .MODULUS_BIT_WIDTH (KEY_SIZE),
      .WORD_BIT_WIDTH    (RADIX)
  ) rsa_crt_garner_i (
      .clk               (clk),
      .rst_n             (rst_n),
      .zeroize           (zeroize),
      .start_in          (gn_start),
      .m1_in             (m1_reg),
      .m2_in             (m2_reg),
      .p_in              (KEY_SIZE'(p_reg)),
      .q_in              (KEY_SIZE'(q_reg)),
      .qinv_in           (KEY_SIZE'(qinv_reg)),
      .r_pow_2_mod_p_in  (KEY_SIZE'(r2_p)),
      .mm_req_out        (gn_mm_req),
      .mul_req_out       (gn_mul_req),
      .mm_half_out       (gn_mm_half),
      .mm_a_out          (gn_mm_a),
      .mm_b_out          (gn_mm_b),
      .mm_done_in        (me_done_i),
      .mm_result_in      (me_result_i),
      .mul_product_in    (me_product_i),
      .result_out        (gn_result),
      .done_out          (gn_done),
      .busy_out          (gn_busy)
  );

  always_comb gn_start = (state == GARNER_REQ_ST);

  // ---------------------------------------------------------------------
  // Next state
  // ---------------------------------------------------------------------
  always_comb begin
    state_next = state;
    unique case (state)
      IDLE_ST        : if      (ldmod_start_i) state_next = LD_PQ_REQ_ST;
                       else if (exp_start_i)   state_next = BR_RED1_REQ_ST;

      LD_PQ_REQ_ST   :                       state_next = LD_PQ_WAIT_ST;
      LD_PQ_WAIT_ST  : if (mc_done_i)        state_next = LD_N_REQ_ST;
      LD_N_REQ_ST    :                       state_next = LD_N_WAIT_ST;
      LD_N_WAIT_ST   : if (mc_done_i)        state_next = LD_DONE_ST;
      LD_DONE_ST     :                       state_next = IDLE_ST;

      BR_RED1_REQ_ST :                       state_next = BR_RED1_WAIT_ST;
      // Geometry is shared by overlapping multiplies.  Leave a clear cycle
      // after retirement before switching full/half/dual modes.
      BR_RED1_WAIT_ST: if (me_done_i)        state_next = BR_RED1_GAP_ST;
      BR_RED1_GAP_ST :                       state_next = BR_RED2_REQ_ST;
      BR_RED2_REQ_ST :                       state_next = BR_RED2_WAIT_ST;
      BR_RED2_WAIT_ST: if (me_done_i)        state_next = BR_RED2_GAP_ST;
      // Reduce p then q before launching the shared dual ladder.
      BR_RED2_GAP_ST :                       state_next = BR_NEXT_ST;
      // Separate branch requests so no mode change overlaps an in-flight MM.
      BR_NEXT_ST     : state_next = branch ? BR_EXP_REQ_ST : BR_RED1_REQ_ST;
      BR_EXP_REQ_ST  :                       state_next = BR_EXP_WAIT_ST;
      BR_EXP_WAIT_ST : if (me_done_i)        state_next = BR_EXP_GAP_ST;
      // Drain dual mode before Garner's single half-width MM.
      BR_EXP_GAP_ST  :                       state_next = GARNER_REQ_ST;

      GARNER_REQ_ST  :                       state_next = GARNER_WAIT_ST;
      GARNER_WAIT_ST : if (gn_done)          state_next = BELL_REQ_ST;

      BELL_REQ_ST    :                       state_next = BELL_WAIT_ST;
      BELL_WAIT_ST   : if (me_done_i)        state_next = CHECK_ST;
      CHECK_ST       :                       state_next = EXP_DONE_ST;
      EXP_DONE_ST    :                       state_next = IDLE_ST;
      default        :                       state_next = IDLE_ST;
    endcase
  end

  // ---------------------------------------------------------------------
  // Registers
  // ---------------------------------------------------------------------
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      state     <= IDLE_ST;
      branch    <= 1'b0;
      x_reg     <= '0;
      n_reg     <= '0;
      p_reg     <= '0;
      q_reg     <= '0;
      qinv_reg  <= '0;
      dp_reg    <= '0;
      dq_reg    <= '0;
      e_reg     <= '0;
      e_msb_reg <= '0;
      np_p      <= '0;
      np_q      <= '0;
      r1_p      <= '0;
      r1_q      <= '0;
      r2_p      <= '0;
      r2_q      <= '0;
      ctx_valid <= 1'b0;
      red_reg   <= '0;
      redp_reg  <= '0;
      redq_reg  <= '0;
      m1_reg    <= '0;
      m2_reg    <= '0;
      m_reg     <= '0;
      fault_reg <= 1'b0;
    end else if (zeroize) begin
      state     <= IDLE_ST;
      branch    <= 1'b0;
      x_reg     <= '0;
      n_reg     <= '0;
      p_reg     <= '0;
      q_reg     <= '0;
      qinv_reg  <= '0;
      dp_reg    <= '0;
      dq_reg    <= '0;
      e_reg     <= '0;
      e_msb_reg <= '0;
      np_p      <= '0;
      np_q      <= '0;
      r1_p      <= '0;
      r1_q      <= '0;
      r2_p      <= '0;
      r2_q      <= '0;
      ctx_valid <= 1'b0;
      red_reg   <= '0;
      redp_reg  <= '0;
      redq_reg  <= '0;
      m1_reg    <= '0;
      m2_reg    <= '0;
      m_reg     <= '0;
      fault_reg <= 1'b0;
    end else begin
      state <= state_next;

      if (state == IDLE_ST) begin
        if (ldmod_start_i) begin
          // Bind n, p, q and qinv to this LDMOD until reload or zeroization.
          n_reg     <= n_i;
          p_reg     <= p_i[HALF_SIZE-1:0];
          q_reg     <= q_i[HALF_SIZE-1:0];
          qinv_reg  <= qinv_i[HALF_SIZE-1:0];
          ctx_valid <= 1'b0;
        end
        if (exp_start_i) begin
          x_reg     <= base_i;
          dp_reg    <= dp_i[HALF_SIZE-1:0];
          dq_reg    <= dq_i[HALF_SIZE-1:0];
          e_reg     <= e_i;
          e_msb_reg <= e_msb_index_i;
          branch    <= 1'b0;
          fault_reg <= 1'b0;
          m_reg     <= '0;
        end
      end

      // One derivation, both contexts: p came out of lane 0 and q out of lane 1.
      if ((state == LD_PQ_WAIT_ST) && mc_done_i) begin
        np_p <= mc_n_prime_i;
        r1_p <= mc_r1_i[HALF_SIZE-1:0];
        r2_p <= mc_r2_i[HALF_SIZE-1:0];
        np_q <= mc_n_prime1_i;
        r1_q <= mc_r1_1_i[HALF_SIZE-1:0];
        r2_q <= mc_r2_1_i[HALF_SIZE-1:0];
      end
      if (state == LD_DONE_ST) ctx_valid <= 1'b1;
      if (ctx_invalidate_i)    ctx_valid <= 1'b0;

      // s1 = MM_full(x, r2) = x * 2^RADIX mod modulus
      // red = MM_half(s1, T) = x mod modulus
      if (((state == BR_RED1_WAIT_ST) || (state == BR_RED2_WAIT_ST)) && me_done_i)
        red_reg <= me_result_i;

      // Preserve both reduced bases for simultaneous consumption by the ladder.
      if ((state == BR_RED2_WAIT_ST) && me_done_i) begin
        if (branch) redq_reg <= me_result_i[HALF_SIZE-1:0];
        else        redp_reg <= me_result_i[HALF_SIZE-1:0];
      end

      // Both branch results retire together: lane 0 is p, lane 1 is q.
      if ((state == BR_EXP_WAIT_ST) && me_done_i) begin
        m1_reg <= me_result_i;
        m2_reg <= me_result1_i;
      end

      if (state == BR_NEXT_ST) branch <= 1'b1;

      if ((state == GARNER_WAIT_ST) && gn_done) m_reg <= gn_result;

      // The fault check.  m^e mod n must equal x; tessera_rsa_ctrl is told to discard
      // the result if it does not.
      if ((state == BELL_WAIT_ST) && me_done_i)
        fault_reg <= (me_result_i != x_reg);
    end
  end

  // ---------------------------------------------------------------------
  // Borrowed-unit drive
  // ---------------------------------------------------------------------
  always_comb begin
    mc_start_o = (state == LD_PQ_REQ_ST) || (state == LD_N_REQ_ST);
    // Hold geometry and context through REQ and WAIT so the borrowed R^2
    // chain keeps the correct modulus.  Prime contexts are half width; n is full.
    mc_half_o  = (state == LD_PQ_REQ_ST) || (state == LD_PQ_WAIT_ST);
    // Keep lane 1 selected throughout the borrowed chain.
    mc_dual_o  = mc_half_o;
    unique case (state)
      LD_PQ_REQ_ST, LD_PQ_WAIT_ST: mc_n_o = KEY_SIZE'(p_reg);
      default                    : mc_n_o = n_reg;
    endcase
    mc_n1_o = KEY_SIZE'(q_reg);
  end

  // Fixed lane-width bound, independent of dp/dq; HALF_SIZE-1 at native width.
  logic [EXP_IDX_W-1:0] BRANCH_MSB_IDX;
  assign BRANCH_MSB_IDX = lane_bits - EXP_IDX_W'(1);

  always_comb begin
    me_start_o      = 1'b0;
    me_mul_mode_o   = 1'b0;
    me_mm_mode_o    = 1'b0;
    me_mm_half_o    = 1'b0;
    me_half_o       = 1'b0;
    me_exp_public_o = 1'b0;
    me_base_o       = '0;
    me_mul_b_o      = '0;
    me_exponent_o   = '0;
    me_msb_index_o  = '0;
    // Keep the branch context valid during WAIT as well as request states.
    me_n_o          = KEY_SIZE'(br_mod);
    me_n_prime_o    = br_nprime;
    me_r1_o         = KEY_SIZE'(br_r1);
    me_r2_o         = KEY_SIZE'(br_r2);
    // Lane 1 is driven only by the dual branch ladder.
    me_dual_o       = 1'b0;
    me_base1_o      = '0;
    me_exponent1_o  = '0;
    me_n1_o         = KEY_SIZE'(q_reg);
    me_n_prime1_o   = np_q;
    me_r11_o        = KEY_SIZE'(r1_q);
    me_r21_o        = KEY_SIZE'(r2_q);

    unique case (state)
      // Full-width MM consumes all of x; service geometry is sampled on start.
      BR_RED1_REQ_ST: begin
        me_start_o   = 1'b1;
        me_mm_mode_o = 1'b1;
        me_mm_half_o = 1'b0;
        me_base_o    = x_reg;
        me_mul_b_o   = KEY_SIZE'(br_r2);
      end
      // (x * 2^RADIX) * 2^(KEY/2) * R_half^-1 = x mod br_mod.
      BR_RED2_REQ_ST: begin
        me_start_o   = 1'b1;
        me_mm_mode_o = 1'b1;
        me_mm_half_o = 1'b1;
        me_base_o    = red_reg;
        me_mul_b_o   = KEY_SIZE'(br_t);
      end
      // Hold all dual-ladder inputs through REQ and WAIT; only start pulses.
      // Both secret lanes share BRANCH_MSB_IDX with public shortcuts disabled.
      // branch now selects q, so lane 0 must override the defaults with p.
      BR_EXP_REQ_ST, BR_EXP_WAIT_ST: begin
        me_start_o      = (state == BR_EXP_REQ_ST);
        me_half_o       = 1'b1;
        me_dual_o       = 1'b1;
        me_base_o       = KEY_SIZE'(redp_reg);
        me_exponent_o   = EXP_SIZE'(dp_reg);
        me_n_o          = KEY_SIZE'(p_reg);
        me_n_prime_o    = np_p;
        me_r1_o         = KEY_SIZE'(r1_p);
        me_r2_o         = KEY_SIZE'(r2_p);
        me_base1_o      = KEY_SIZE'(redq_reg);
        me_exponent1_o  = EXP_SIZE'(dq_reg);
        me_msb_index_o  = BRANCH_MSB_IDX;
        // dp and dq are secret.  Never licence the public shortcuts here.
        me_exp_public_o = 1'b0;
      end
      // Garner borrows the array for two half MMs mod p and one full unreduced
      // multiply.  Its context is p, not br_mod -- branch is 1 at this point.
      GARNER_REQ_ST, GARNER_WAIT_ST: begin
        me_start_o    = gn_mm_req | gn_mul_req;
        me_mm_mode_o  = gn_mm_req;
        me_mul_mode_o = gn_mul_req;
        me_mm_half_o  = gn_mm_half;
        me_base_o     = gn_mm_a;
        me_mul_b_o    = gn_mm_b;
        me_n_o        = KEY_SIZE'(p_reg);
        me_n_prime_o  = np_p;
        me_r1_o       = KEY_SIZE'(r1_p);
        me_r2_o       = KEY_SIZE'(r2_p);
      end
      // Bellcore: m^e mod n, full width, against the resident n context.  Held
      // across REQ and WAIT for the same reason as the branch ladder.
      BELL_REQ_ST, BELL_WAIT_ST: begin
        me_start_o      = (state == BELL_REQ_ST);
        me_base_o       = m_reg;
        me_exponent_o   = e_reg;
        me_msb_index_o  = e_msb_reg;
        // Verification may use public-e shortcuts.
        me_exp_public_o = 1'b1;
        // The n context lives in tessera_rsa_mont_const; tessera_rsa_ctrl routes it.
        me_n_o          = n_reg;
        me_n_prime_o    = mc_n_prime_i;
        me_r1_o         = mc_r1_i;
        me_r2_o         = mc_r2_i;
      end
      default: ;
    endcase
  end

  // ---------------------------------------------------------------------
  // Outputs
  // ---------------------------------------------------------------------
  always_comb begin
    // Retain ownership while the sequencer or recombination unit is active.
    crt_active_o = (state != IDLE_ST) || gn_busy;
    ctx_valid_o  = ctx_valid;
    // Suppress faulted signatures rather than merely reporting an error.
    result_o     = fault_reg ? KEY_SIZE'(0) : m_reg;
    done_o       = (state == LD_DONE_ST) || (state == EXP_DONE_ST);
    fault_o      = (state == EXP_DONE_ST) && fault_reg;
  end


// synthesis translate_off
// ---------------------------------------------------------------------------
// Simulation-only CRT state-cycle profiling.  Counters are cumulative; take
// deltas between reports.  Keep disabled in measurement builds.
// ---------------------------------------------------------------------------
`ifdef RSA_MODEXP_PROFILE
  int unsigned crtp_cyc [0:31];
  int unsigned crtp_ops;
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n || zeroize) begin
      for (int j = 0; j < 32; j++) crtp_cyc[j] <= 0;
      crtp_ops <= 0;
    end
    else begin
      if (state != IDLE_ST)
        crtp_cyc[int'(state)] <= crtp_cyc[int'(state)] + 1;
      if (state == EXP_DONE_ST) begin
        crtp_ops <= crtp_ops + 1;
        $display("RSA_CRT_PROFILE op=%0d", crtp_ops);
        for (int j = 0; j < 32; j++)
          if (crtp_cyc[j] != 0)
            $display("RSA_CRT_PROFILE   state[%0d] = %0d cycles", j, crtp_cyc[j]);
      end
    end
  end
`endif
// synthesis translate_on


  // ---------------------------------------------------------------------
  // Elaboration guards
  // ---------------------------------------------------------------------
  if ((KEY_SIZE % (2 * RADIX)) != 0)
    $fatal(1, "tessera_rsa_crt_ctrl: KEY_SIZE (%0d) must be an even number of %0d-bit words.",
           KEY_SIZE, RADIX);
  if (HALF_SIZE > EXP_SIZE)
    $fatal(1, "tessera_rsa_crt_ctrl: HALF_SIZE (%0d) does not fit the exponent port (%0d).",
           HALF_SIZE, EXP_SIZE);

endmodule
