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
// tessera_rsa_pe_lane1_boundary.sv
// ------------------------
// Shared middle/head PE slot at the lane-1 boundary.
//
// Description:
//      dual_sel selects lane 1's quotient-generating head or the single-lane
//      middle PE. Their common b/p words allow two full-width multipliers
//      to be shared by muxing only a/m. Head-only quotient multipliers stay local.
//
//      Sharing requires these invariants:
//      - The inactive PE's state is invalid. Both PEs clear on start_in or
//        zeroize; in dual mode start_in equals start_i, clearing the head
//        before use.
//      - The middle PE's s_out always drives s_array[LANE1_S0-1], but must
//        remain unread in dual mode. All consumers use s_eff: at lane 0's
//        terminator it selects last_s_reg, and taps above that are inactive.
//      - dual_sel must remain stable throughout a multiply and any overlapped
//        chain. The parent uses start_i ? dual_i : dual_reg and checks mode changes.
//
//      Select by dual_sel, not half_reg or lane 0's tap_base; lane 1 has
//      independent geometry through tap_base_1.
//
//======================================================================

module tessera_rsa_pe_lane1_boundary #(
    parameter RADIX = 32
)
(
    // Clock and reset.
    input  wire              clk,
    input  wire              reset_n,

    input  wire              start_in,
    input  wire              zeroize,

    // High exactly when this slot is acting as lane 1's head.
    input  wire              dual_sel,

    // Shared between the two boxes at this slot.
    input  wire [RADIX-1:0]  b_in,
    input  wire [RADIX-1:0]  p_in,
    input  wire [RADIX-1:0]  s_in,
    input  wire              odd,

    // Middle-PE (single-lane) side.
    input  wire [RADIX-1:0]  a_in,
    input  wire [RADIX-1:0]  m_in,
    input  wire [RADIX  :0]  c_in,

    // Head (lane 1) side.
    input  wire [RADIX-1:0]  a1_in,
    input  wire [RADIX-1:0]  n_prime1_in,
    input  wire [RADIX-1:0]  bn1_in,

    // Muxed on dual_sel.
    output logic [RADIX-1:0] a_out,
    output logic [RADIX-1:0] m_out,
    output logic [RADIX  :0] c_out,
    // Unmuxed middle-PE output; must remain unread in dual mode.
    output logic [RADIX-1:0] s_out
);

    logic [2*RADIX-1:0] prod_ab;
    logic [2*RADIX-1:0] prod_pm;

    logic [RADIX-1:0]   f1_mul_a;
    logic [RADIX-1:0]   f1_mul_m;
    logic [RADIX-1:0]   mul_a_sel;
    logic [RADIX-1:0]   mul_m_sel;

    logic [RADIX-1:0]   pe_a_out;
    logic [RADIX-1:0]   pe_m_out;
    logic [RADIX  :0]   pe_c_out;

    logic [RADIX-1:0]   f1_a_out;
    logic [RADIX-1:0]   f1_m_out;
    logic [RADIX  :0]   f1_c_out;
    logic [RADIX-1:0]   f1_low_unused;

    // b_in and p_in are common to both PEs; only a/m need selection.
    assign mul_a_sel = dual_sel ? f1_mul_a : a_in;
    assign mul_m_sel = dual_sel ? f1_mul_m : m_in;

    tessera_rsa_mult_dsp #(
        .RADIX(RADIX)
    ) MULT_AB (
        .A(mul_a_sel),
        .B(b_in),
        .P(prod_ab)
    );

    tessera_rsa_mult_dsp #(
        .RADIX(RADIX)
    ) MULT_PM (
        .A(p_in),
        .B(mul_m_sel),
        .P(prod_pm)
    );

    tessera_rsa_pe #(
        .RADIX(RADIX),
        .EXT_MULT(1)
        )
        box_i
        (
        .clk(clk),
        .reset_n(reset_n),
        .start_in(start_in),
        .zeroize(zeroize),
        .a_in(a_in),
        .b_in(b_in),
        .p_in(p_in),
        .m_in(m_in),
        .s_in(s_in),
        .c_in(c_in),
        .odd(odd),
        .ext_ab_in(prod_ab),
        .ext_pm_in(prod_pm),

        .a_out(pe_a_out),
        .m_out(pe_m_out),
        .s_out(s_out),
        .c_out(pe_c_out)
        );

    tessera_rsa_pe_first #(
        .RADIX(RADIX),
        .EXT_MULT(1)
        )
        first_box_1
        (
        .clk(clk),
        .reset_n(reset_n),
        .start_in(start_in),
        .zeroize(zeroize),
        // Shared a shift register, tapped MOD_WORDS_H+1 words above lane 0.
        .a_in(a1_in),
        .b_in(b_in),
        .p_in(p_in),
        .s_in(s_in),
        .n_prime_in(n_prime1_in),
        // Matches b_in at word LANE1_W0 in dual mode. Otherwise this head's
        // outputs are unselected, so the constant need not match the middle tap.
        .bn0_in(bn1_in),
        .odd(odd),
        .ext_ab_in(prod_ab),
        .ext_pm_in(prod_pm),

        .mul_a_o(f1_mul_a),
        .mul_m_o(f1_mul_m),

        .a_out(f1_a_out),
        .m_out(f1_m_out),
        .c_out(f1_c_out),
        .low_out(f1_low_unused)
        );

    assign a_out = dual_sel ? f1_a_out : pe_a_out;
    assign m_out = dual_sel ? f1_m_out : pe_m_out;
    assign c_out = dual_sel ? f1_c_out : pe_c_out;

endmodule
