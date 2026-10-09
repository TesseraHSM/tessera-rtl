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
// tessera_rsa_crt_garner.sv
// -----------------
// Garner recombination for a CRT exponentiation.
//
// For m1 = x^dp mod p and m2 = x^dq mod q:
//     m  = m2 + q * ((m1 - m2) * qinv mod p)        where qinv = q^-1 mod p
//
// This is the unique value below n=p*q with the required branch residues.
// Unlike symmetric CRT, Garner needs no full-width modular reduction:
// two half-width Montgomery multiplies, one unreduced multiply and an add suffice.
//
// Borrow tessera_rsa_modexp's array with its p context selected.  mm_req_out computes
// a*b*R_half^-1 mod p; mul_req_out computes a*b without reduction.  The former
// requires half-width geometry and constants; the latter requires full width
// to preserve the KEY-bit product of two half-width operands.
//
// The schedule is independent of all secret operands.  Two unconditional
// subtractions and borrow selects normalize m1+2p-m2 without timing variation.
//
//======================================================================

module tessera_rsa_crt_garner
  import tessera_rsa_params_pkg::*;
#(
    parameter   MODULUS_BIT_WIDTH   = RSA_KEY_SIZE,
    parameter   WORD_BIT_WIDTH      = RSA_RADIX,

    // Half-width operands use full-width buses with zero upper halves.
    localparam  int unsigned HALF_BIT_WIDTH = MODULUS_BIT_WIDTH / 2
)
(
    input  wire                                 clk,
    input  wire                                 rst_n,
    input  wire                                 zeroize,

    input  wire                                 start_in,

    // Branch results.  m1 < p and m2 < q.
    input  wire  [MODULUS_BIT_WIDTH-1:0]        m1_in,
    input  wire  [MODULUS_BIT_WIDTH-1:0]        m2_in,

    // Key material.  qinv = q^-1 mod p.
    input  wire  [MODULUS_BIT_WIDTH-1:0]        p_in,
    input  wire  [MODULUS_BIT_WIDTH-1:0]        q_in,
    input  wire  [MODULUS_BIT_WIDTH-1:0]        qinv_in,

    // R_half^2 mod p from a half-width context; the first MM enters Montgomery
    // form and the second returns an ordinary integer.
    input  wire  [MODULUS_BIT_WIDTH-1:0]        r_pow_2_mod_p_in,

    // Borrowed array.  Both request outputs are single-cycle pulses.
    output logic                                mm_req_out,
    output logic                                mul_req_out,
    output logic                                mm_half_out,
    output logic [MODULUS_BIT_WIDTH-1:0]        mm_a_out,
    output logic [MODULUS_BIT_WIDTH-1:0]        mm_b_out,
    // tessera_rsa_modexp completion for either request kind.
    input  wire                                 mm_done_in,
    input  wire  [MODULUS_BIT_WIDTH-1:0]        mm_result_in,
    // Low 2*MODULUS_BIT_WIDTH bits of product_out, excluding Montgomery padding.
    input  wire  [2*MODULUS_BIT_WIDTH-1:0]      mul_product_in,

    output logic [MODULUS_BIT_WIDTH-1:0]        result_out,
    output logic                                done_out,
    output logic                                busy_out
);

  //----------------------------------------------------------------
  // FSM
  //----------------------------------------------------------------
  localparam [3:0] IDLE_ST     = 4'd0,
                   SUB_ST      = 4'd1,
                   MM1_REQ_ST  = 4'd2,
                   MM1_WAIT_ST = 4'd3,
                   MM2_REQ_ST  = 4'd4,
                   MM2_WAIT_ST = 4'd5,
                   MUL_REQ_ST  = 4'd6,
                   MUL_WAIT_ST = 4'd7,
                   ADD_ST      = 4'd8,
                   DONE_ST     = 4'd9;

  logic [3:0]                       state, state_next;

  logic [MODULUS_BIT_WIDTH-1:0]     m1_reg;
  logic [MODULUS_BIT_WIDTH-1:0]     m2_reg;
  logic [MODULUS_BIT_WIDTH-1:0]     p_reg;
  logic [MODULUS_BIT_WIDTH-1:0]     q_reg;
  logic [MODULUS_BIT_WIDTH-1:0]     qinv_reg;
  logic [MODULUS_BIT_WIDTH-1:0]     r2_reg;
  logic [MODULUS_BIT_WIDTH-1:0]     t_reg;
  logic [MODULUS_BIT_WIDTH-1:0]     u_reg;
  logic [MODULUS_BIT_WIDTH-1:0]     result_reg;

  //----------------------------------------------------------------
  // Equal-bit-length primes give q < 2p.  With m1 < p and m2 < q:
  //   0 < m1 + 2p - m2 < 3p.
  // The bias avoids a signed intermediate; two conditional subtractions
  // reduce it into [0,p).  Two extra bits prevent overflow at 3p.
  //----------------------------------------------------------------
  localparam int unsigned DIFF_WIDTH = HALF_BIT_WIDTH + 2;

  logic [DIFF_WIDTH-1:0]            diff_biased;
  logic [DIFF_WIDTH-1:0]            diff_sub1;
  logic [DIFF_WIDTH-1:0]            diff_sub2;
  logic [DIFF_WIDTH-1:0]            diff_stage1;
  logic [DIFF_WIDTH-1:0]            diff_stage2;
  logic                             borrow1;
  logic                             borrow2;

  always_comb begin : difference
    // Captured operands allow the caller to release inputs after start_in.
    diff_biased = {{(DIFF_WIDTH-HALF_BIT_WIDTH){1'b0}}, m1_reg[HALF_BIT_WIDTH-1:0]}
                + {{(DIFF_WIDTH-HALF_BIT_WIDTH-1){1'b0}}, p_reg[HALF_BIT_WIDTH-1:0], 1'b0}
                - {{(DIFF_WIDTH-HALF_BIT_WIDTH){1'b0}}, m2_reg[HALF_BIT_WIDTH-1:0]};

    // Borrow selects preserve an operand-independent schedule.
    {borrow1, diff_sub1} = {1'b0, diff_biased}
                         - {1'b0, {{(DIFF_WIDTH-HALF_BIT_WIDTH){1'b0}},
                                   p_reg[HALF_BIT_WIDTH-1:0]}};
    diff_stage1 = borrow1 ? diff_biased : diff_sub1;

    {borrow2, diff_sub2} = {1'b0, diff_stage1}
                         - {1'b0, {{(DIFF_WIDTH-HALF_BIT_WIDTH){1'b0}},
                                   p_reg[HALF_BIT_WIDTH-1:0]}};
    diff_stage2 = borrow2 ? diff_stage1 : diff_sub2;
  end

  //----------------------------------------------------------------
  // Next state
  //----------------------------------------------------------------
  always_comb begin : fsm_next
    state_next = state;
    unique case (state)
      IDLE_ST:     if (start_in)   state_next = SUB_ST;
      SUB_ST:                      state_next = MM1_REQ_ST;
      MM1_REQ_ST:                  state_next = MM1_WAIT_ST;
      MM1_WAIT_ST: if (mm_done_in) state_next = MM2_REQ_ST;
      MM2_REQ_ST:                  state_next = MM2_WAIT_ST;
      MM2_WAIT_ST: if (mm_done_in) state_next = MUL_REQ_ST;
      MUL_REQ_ST:                  state_next = MUL_WAIT_ST;
      MUL_WAIT_ST: if (mm_done_in) state_next = ADD_ST;
      ADD_ST:                      state_next = DONE_ST;
      DONE_ST:                     state_next = IDLE_ST;
      default:                     state_next = IDLE_ST;
    endcase
  end

  //----------------------------------------------------------------
  // Datapath registers
  //----------------------------------------------------------------
  always_ff @(posedge clk or negedge rst_n) begin : datapath
    if (!rst_n) begin
      state      <= IDLE_ST;
      m1_reg     <= '0;
      m2_reg     <= '0;
      p_reg      <= '0;
      q_reg      <= '0;
      qinv_reg   <= '0;
      r2_reg     <= '0;
      t_reg      <= '0;
      u_reg      <= '0;
      result_reg <= '0;
    end
    else if (zeroize) begin
      state      <= IDLE_ST;
      m1_reg     <= '0;
      m2_reg     <= '0;
      p_reg      <= '0;
      q_reg      <= '0;
      qinv_reg   <= '0;
      r2_reg     <= '0;
      t_reg      <= '0;
      u_reg      <= '0;
      result_reg <= '0;
    end
    else begin
      state <= state_next;

      if ((state == IDLE_ST) && start_in) begin
        m1_reg   <= m1_in;
        m2_reg   <= m2_in;
        p_reg    <= p_in;
        q_reg    <= q_in;
        qinv_reg <= qinv_in;
        r2_reg   <= r_pow_2_mod_p_in;
      end

      // Capture (m1-m2) mod p one cycle after the operands settle.
      if (state == SUB_ST)
        t_reg <= {{(MODULUS_BIT_WIDTH-HALF_BIT_WIDTH){1'b0}},
                  diff_stage2[HALF_BIT_WIDTH-1:0]};

      // MM1 gives t*R_half mod p; MM2 turns that into t*qinv mod p.
      if (((state == MM1_WAIT_ST) || (state == MM2_WAIT_ST)) && mm_done_in)
        u_reg <= mm_result_in;

      // m2 + q*u < n fits the result width without carry or reduction.
      if (state == ADD_ST)
        result_reg <= mul_product_in[MODULUS_BIT_WIDTH-1:0] + m2_reg;
    end
  end

  //----------------------------------------------------------------
  // Outputs
  //----------------------------------------------------------------
  always_comb begin : outputs
    mm_req_out  = (state == MM1_REQ_ST) || (state == MM2_REQ_ST);
    mul_req_out = (state == MUL_REQ_ST);
    // Half for the two reductions mod p, full for the q*u product.
    mm_half_out = (state == MM1_REQ_ST) || (state == MM2_REQ_ST);

    unique case (state)
      MM1_REQ_ST: begin mm_a_out = t_reg; mm_b_out = r2_reg;   end
      MM2_REQ_ST: begin mm_a_out = u_reg; mm_b_out = qinv_reg; end
      MUL_REQ_ST: begin mm_a_out = q_reg; mm_b_out = u_reg;    end
      default:    begin mm_a_out = '0;    mm_b_out = '0;       end
    endcase

    result_out = result_reg;
    done_out   = (state == DONE_ST);
    busy_out   = (state != IDLE_ST);
  end

  //----------------------------------------------------------------
  // Runtime guard
  //----------------------------------------------------------------
  // The reduction bound requires q < 2p, as for equal-bit-length RSA primes.
  // This guard is simulation-only; hardware relies on downstream Bellcore
  // verification to withhold an incorrect result.
  //synopsys translate_off
  always_ff @(posedge clk) begin
    if (rst_n && !zeroize && start_in && (state == IDLE_ST)) begin
      if (q_in >= {p_in[MODULUS_BIT_WIDTH-2:0], 1'b0})
        $error("tessera_rsa_crt_garner: Garner recombination requires q < 2p");
    end
  end
  //synopsys translate_on

  //----------------------------------------------------------------
  // Elaboration guards
  //----------------------------------------------------------------
  initial begin
    if (MODULUS_BIT_WIDTH % (2 * WORD_BIT_WIDTH) != 0)
      $fatal(1, "tessera_rsa_crt_garner: MODULUS_BIT_WIDTH (%0d) must be an even number of %0d-bit words; the half-width CRT path splits it exactly in two.",
             MODULUS_BIT_WIDTH, WORD_BIT_WIDTH);
  end

endmodule
