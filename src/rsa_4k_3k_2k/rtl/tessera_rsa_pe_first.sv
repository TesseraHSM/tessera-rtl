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
// tessera_rsa_pe_first.sv
// ---------------
// First processing element for the systolic Montgomery multiplier.
//
// Description:
//      Accumulates partial products and broadcasts the Montgomery quotient
//      digit m. With n_prime_in = bn0_in = 0, reduction is disabled and
//      low_out supplies the low words of the plain integer product.
//
//      Distributing n_prime avoids a MULT -> ADD -> MULT critical path:
//          m = ((s + a*b0) * n_prime) mod 2^RADIX
//            = (s*n_prime + a*bn0_in) mod 2^RADIX
//      The caller precomputes bn0_in = (b0*n_prime) mod 2^RADIX once per
//      multiply. The two quotient products then run in parallel into one
//      RADIX-bit adder; truncation implements the exact modular identity.
//
//======================================================================

module tessera_rsa_pe_first #(
    parameter RADIX = 32,
    // Share full-width products at the lane-1 boundary by exporting a and
    // m_temp_reg. The head-only truncated quotient multipliers remain local.
    parameter EXT_MULT = 0
)
(
    // Clock and reset.
    input  wire              clk,
    input  wire              reset_n,

    input  wire              start_in,
    // Synchronous secret erase of all PE registers, sharing the start clear path.
    input  wire              zeroize,
    // DATA PORT
    input  wire [RADIX-1:0]  a_in,
    input  wire [RADIX-1:0]  b_in,
    input  wire [RADIX-1:0]  p_in,
    input  wire [RADIX-1:0]  s_in,
    input  wire [RADIX-1:0]  n_prime_in,
    // Per-multiply (b0*n_prime) mod 2^RADIX; b0 must match b_in.
    // Must be zero whenever n_prime_in is zero.
    input  wire [RADIX-1:0]  bn0_in,
    input  wire              odd,

    // EXT_MULT only.  Products of the operands exported on mul_a_o / mul_m_o
    // below: ext_ab_in == mul_a_o * b_in, ext_pm_in == mul_m_o * p_in.
    input  wire [2*RADIX-1:0] ext_ab_in,
    input  wire [2*RADIX-1:0] ext_pm_in,

    // Always-driven multiplier operands; ignored unless EXT_MULT.
    output logic [RADIX-1:0] mul_a_o,
    output logic [RADIX-1:0] mul_m_o,

    output logic [RADIX-1:0] a_out,
    output logic [RADIX-1:0] m_out,
    output logic [RADIX  :0] c_out,

    // Retired low word: zero after Montgomery cancellation, or a low product
    // word in non-reducing mode.
    output logic [RADIX-1:0] low_out
);


    //----------------------------------------------------------------
    // tessera_rsa_pe_first
    //----------------------------------------------------------------
    logic  [RADIX-1:0]        s_reg;
    logic  [RADIX-1:0]        s;
    logic  [RADIX-1:0]        a_reg;
    logic  [RADIX-1:0]        a;

    logic  [2*RADIX-1 : 0]    mult_out;
    logic  [RADIX-1 : 0]      mult_out_MSW;
    logic  [RADIX-1 : 0]      mult_out_LSW;

    logic  [RADIX   : 0]      res_0;
    logic  [RADIX-1 : 0]      sum_0;
    logic                     carry_0;
    logic  [RADIX-1 : 0]      sum_0_reg;
    logic                     carry_0_reg;

    logic  [RADIX   : 0]      res_1;
    logic  [RADIX-1 : 0]      sum_1;
    logic                     carry_1;

    logic  [RADIX   : 0]      c_0;
    logic  [RADIX   : 0]      c_0_reg;
    logic  [RADIX   : 0]      c_1;

    logic  [RADIX-1 : 0]      mult_out_1;
    logic  [RADIX-1 : 0]      mult_out_3;
    logic  [RADIX-1 : 0]      m_temp;
    logic  [RADIX-1 : 0]      m_temp_reg;

    logic  [2*RADIX-1 : 0]    mult_out_2;
    logic  [RADIX-1 : 0]      mult_out_2_MSW;
    logic  [RADIX-1 : 0]      mult_out_2_LSW;

    logic [RADIX-1:0] a_out_reg;
    logic [RADIX-1:0] m_out_reg;
    logic [RADIX  :0] c_out_reg;

    generate
        if (EXT_MULT) begin : gen_ext_mult
            assign mult_out   = ext_ab_in;
            assign mult_out_2 = ext_pm_in;
        end else begin : gen_own_mult
            tessera_rsa_mult_dsp #(
                .RADIX(RADIX)
            ) MULT0 (
                .A(a),
                .B(b_in),
                .P(mult_out)
            );

            tessera_rsa_mult_dsp #(
                .RADIX(RADIX)
            ) MULT2 (
                .A(m_temp_reg),
                .B(p_in),
                .P(mult_out_2)
            );
        end
    endgenerate

    assign mul_a_o = a;
    assign mul_m_o = m_temp_reg;

    // Quotient products need only their low RADIX bits.
    tessera_rsa_mult_low #(
        .RADIX(RADIX)
    ) MULT1 (
        .A(n_prime_in),
        .B(s),
        .P(mult_out_1)
    );

    // Runs in parallel with MULT1 and the full a*b0 product.
    tessera_rsa_mult_low #(
        .RADIX(RADIX)
    ) MULT3 (
        .A(a),
        .B(bn0_in),
        .P(mult_out_3)
    );

    // Truncating the sum completes reduction modulo 2^RADIX.
    assign m_temp = mult_out_1 + mult_out_3;

    assign mult_out_MSW = mult_out[2*RADIX-1 : RADIX];
    assign mult_out_LSW = mult_out[RADIX-1 : 0];
    assign mult_out_2_MSW = mult_out_2[2*RADIX-1 : RADIX];
    assign mult_out_2_LSW = mult_out_2[RADIX-1 : 0];

    assign s = odd ? s_in : s_reg;
    assign a = odd ? a_in : a_reg;

    always_comb begin
        res_0 = {1'b0, s} + {1'b0, mult_out_LSW};
        sum_0 = res_0[RADIX-1 : 0];
        carry_0 = res_0[RADIX];
    end

    always_comb begin
        res_1 = {1'b0, sum_0_reg} + {1'b0, mult_out_2_LSW};
        carry_1 = res_1[RADIX];
    end

    always_comb begin
        c_0 = {1'b0, mult_out_MSW} + carry_0;
    end

    always_comb begin
        c_1 = {1'b0, mult_out_2_MSW} + carry_1;
    end

    always_ff @(posedge clk) begin
        if (zeroize | start_in) begin
            c_0_reg <= 'b0;
            sum_0_reg <= 'b0;
            m_temp_reg <= 'b0;
            s_reg <= 'b0;
            a_reg <= 'b0;
        end else begin
            s_reg <= s_in;
            a_reg <= a_in;
            m_temp_reg <= m_temp;
            c_0_reg <= c_0;
            sum_0_reg <= sum_0;
        end

        if(~reset_n) begin
            c_0_reg <= 'b0;
            sum_0_reg <= 'b0;
            m_temp_reg <= 'b0;
            s_reg <= 'b0;
            a_reg <= 'b0;
        end
    end

    assign c_out = c_0_reg + c_1;

    assign low_out = res_1[RADIX-1 : 0];

    always_ff @(posedge clk) begin
        if (zeroize | start_in) begin
            a_out <= 'b0;
        end else begin
            a_out <= a;
        end

        if (~reset_n) begin
            a_out <= 'b0;
        end
    end

    always_ff @(posedge clk) begin
        if (zeroize | start_in) begin
            m_out <= 'b0;
        end else begin
            m_out <= m_temp;
        end

        if (~reset_n) begin
            m_out <= 'b0;
        end
    end

endmodule