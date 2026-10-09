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
// tessera_rsa_montgomerymultiplier.sv
// ---------------------------
// Systolic Montgomery multiplier for the RSA accelerator.
//
// Based on "Optimized Algorithms and Architectures for Montgomery
// Multiplication for Post-quantum Cryptography", Rami Elkhatib et al.
//
// Description:
//      Montgomery multiplication for opa_i, opb_i < n_i, with RADIX > 2:
//          R = 2^((ceil($bits(n_i) / RADIX) + 1) * RADIX)
//          R > n_i.
//          T = opa_i * opb_i
//          u = (T + (T*n_prime mod R) * n_i) / R
//      Since u < n_i + n_i^2/R < 2*n_i, one conditional subtraction
//      produces a canonical result below n_i when reduce_i is set.
//
//      Non-reducing mode forces the quotient digit to zero. product_o
//      combines the array result with low words captured from the first PE
//      to return the full plain product; n_i and the operand bounds are irrelevant.
//
//      Each PE consumes one b-word per cycle and one a-word per two cycles.
//      Feed takes 2*S_NUM cycles; drain takes S_NUM. Conditional subtraction
//      proceeds with retirement and adds no cycles. The two-cycle cadence
//      follows the Montgomery recurrence:
//          (C,S) = t[j] + a_i*b_j + m_i*n_j + C ;   t[j-1] = S
//      Iteration i+1 needs word j after iteration i processes word j+1.
//      With T(i,p) = i*d + p, T(i+1,p) >= T(i,p+1)+1 requires d >= 2
//      for registered inter-stage feedback.
//
//      Pipelining overlaps one multiply's drain with the next one's feed.
//      Word t is captured at 2*S_NUM+1+t and readable at 2*S_NUM+2+t.
//      Thus the minimum initiation interval is 2*S_NUM+2, with no slack
//      on word 0. It must remain even to preserve the shared odd phase.
//
//      Overlap uses per-stage start pulses, first-step sum masking, and a
//      double-buffered b operand. The modulus and geometry stay constant
//      across the chain. fwd_a_i/fwd_b_i read pre-subtraction retirement
//      words; intermediate products defer final reduction (Walter 1999).
//      accept_o permits a new launch; ready_o reports each retirement.
//      Define RSA_MM_NO_PIPELINE for serialized operation.
//
//======================================================================

//      Dual-lane mode (dual_i, DUAL_EN) partitions the array into independent
//      half-width Montgomery lanes sharing launch, phase and retirement.
//      Lane 1 is offset by NSTAGE_H stages and 2*NSTAGE_H result words:
//
//                      lane 0                 lane 1
//        stages        0 .. NSTAGE_H-1        NSTAGE_H .. 2*NSTAGE_H-1
//        t_reg words   0 .. 2*NSTAGE_H-2      2*NSTAGE_H .. 4*NSTAGE_H-2
//        top carry     last_s_reg             last_s_reg_1
//
//      Separate guard words require one extra PE stage and two result words.
//      The gap at word 2*NSTAGE_H-1 is never retired in dual mode.
//      a_reg packs {a1, zero guard, a0} with fixed taps at words 0 and
//      MOD_WORDS_H+1. b_reg/p_reg place lane 1 at word 2*NSTAGE_H so the
//      existing 2j-1/2j stage taps remain lane-relative.
//      DUAL_EN=0 removes the additional lane hardware.
//
//======================================================================

module tessera_rsa_montgomerymultiplier #(
    parameter   MODULUS_WIDTH   = 384,
    parameter   RADIX           = 32,
    // Enable the additional PE stage, lane-1 head, carry register and operand muxes.
    parameter bit DUAL_EN       = 1'b0,
    // Operand words plus one guard word; also sizes the non-reducing product port.
    localparam  S_NUM           = ((MODULUS_WIDTH + RADIX - 1) / RADIX) + 1,
    localparam  FULL_REG_SIZE   = S_NUM * RADIX
)
(
    // Clock and reset.
    input  wire                             clk,
    input  wire                             reset_n,

    // DATA PORT
    // Launch while idle, or after accept_o for a compatible pipelined multiply.
    input  wire                             start_i,
    // Synchronous secret erase of operands, PE state and results; aborts in-flight work.
    input  wire                             zeroize,
    // Latched at launch. Forces the quotient digit to zero; use product_o
    // for the full plain product. n_i is not needed for this computation.
    input  wire                             nonreducing_i,
    // Final-subtraction enable (Walter 1999), queued from launch to retirement.
    // For reduced inputs, R >= 2^RADIX*n gives u < n*(1 + 2^-RADIX) < 2n.
    // Intermediate multiplies leave this low to forward pre-subtraction
    // words; a closing multiply selects the canonical result.
    // Constant-time selection does not imply constant power: the borrow
    // chain's data-dependent toggling remains a side-channel consideration.
    // Not used for the non-reducing product.
    input  wire                             reduce_i,
    input  wire     [MODULUS_WIDTH-1:0]     opa_i,
    input  wire     [MODULUS_WIDTH-1:0]     opb_i,
    input  wire     [MODULUS_WIDTH-1:0]     n_i,
    input  wire     [RADIX-1:0]             n_prime_i, // only need the last word
    // Latched operand forwarding from the previous multiply's retiring t_reg.
    // The producer must use reduce_i=0 because these words are pre-subtraction.
    // Separate controls allow both operands of a square, or only a in
    // MM(res, tbl[w]), to be forwarded. Ignored unless MM_PIPELINE.
    input  wire                             fwd_a_i,
    input  wire                             fwd_b_i,
    // Default half-width geometry, unless geom_i overrides it: latency
    // 3*S_NUM_H, base interval 2*S_NUM_H+2, and a zero-extended result.
    // Upper stages keep clocking but are not read. Sampled at launch;
    // must stay constant across an overlapped chain to preserve retirement taps.
    input  wire                             half_i,
    // Runtime top-stage index: modulus_width/(2*RADIX), per lane in dual mode.
    // Zero selects the default full/half geometry. Sampled at launch and
    // constant across an overlapped chain. Fixed width because TOPS_W is local.
    input  wire [7:0]                       geom_i,
    // Dual-lane enable; ignored unless DUAL_EN. Defaults both lanes to half
    // width: lane 0 uses the low-half operands and p_o, lane 1 uses *1_i/p1_o.
    // Sampled at launch and constant across an overlapped chain, since it
    // selects the start wavefront. Mutually exclusive with nonreducing_i:
    // only lane 0 has low-product capture.
    input  wire                             dual_i,
    input  wire     [MODULUS_WIDTH/2-1:0]   opa1_i,
    input  wire     [MODULUS_WIDTH/2-1:0]   opb1_i,
    input  wire     [MODULUS_WIDTH/2-1:0]   n1_i,
    input  wire     [RADIX-1:0]             n_prime1_i,
    output logic    [MODULUS_WIDTH-1:0]     p_o,
    // Lane 1 result, zero-extended to the full port width exactly like p_o in
    // half mode.  Constant zero unless DUAL_EN.
    output logic    [MODULUS_WIDTH-1:0]     p1_o,
    output logic    [2*FULL_REG_SIZE-1:0]   product_o,
    output logic                            ready_o,
    // Permits a new launch; equals ready_o when pipelining is disabled.
    output logic                            accept_o
);
    //----------------------------------------------------------------
    // Local Parameters
    //----------------------------------------------------------------
    // Two words per middle PE; excludes the separately instantiated final PE.
    // See section 4.2 of Khatib_2019.
    localparam  PE_UNITS        = (S_NUM - 1) / 2 - 1;
    localparam  LOW_CNT_WIDTH   = $clog2(S_NUM + 1);

    // ------------------------------------------------------------------
    // Half-width (CRT) geometry.
    // ------------------------------------------------------------------
    localparam  MODULUS_WIDTH_H = MODULUS_WIDTH / 2;
    localparam  S_NUM_H         = ((MODULUS_WIDTH_H + RADIX - 1) / RADIX) + 1;
    localparam  PE_UNITS_H      = (S_NUM_H - 1) / 2 - 1;
    // A middle PE can terminate the shortened chain: its sum/carry logic
    // matches tessera_rsa_pe_final; only the unused a_out/m_out registers differ.
    localparam  TOP_STAGE_H     = PE_UNITS_H + 1;
    localparam  NSTAGE_H        = PE_UNITS_H + 2;

    // ------------------------------------------------------------------
    // Dual-lane geometry.
    //
    // PE_UNITS/NSTAGE describe the logical full-width sweep and its timing.
    // _P constants describe physical capacity: one extra stage and two extra
    // result words when DUAL_EN. Do not use physical depth for logical taps.
    // ------------------------------------------------------------------
    localparam int LANE1_S0     = NSTAGE_H;              // lane 1's tessera_rsa_pe_first
    localparam int LANE1_TOP    = 2*NSTAGE_H - 1;        // lane 1's top stage
    localparam int LANE1_W0     = 2*NSTAGE_H;            // lane 1's first t word
    localparam int GAP_W        = LANE1_W0 - 1;          // never retired
    localparam int PE_UNITS_P   = DUAL_EN ? (PE_UNITS + 1) : PE_UNITS;
    localparam int NSTAGE_P     = PE_UNITS_P + 2;
    localparam int TWORDS       = 2*(PE_UNITS_P + 1) + 1;
    // Size b/p buffers through the physical top's odd-phase tap, TWORDS-1.
    localparam int PB_WORDS     = TWORDS;
    localparam int PB_SIZE      = PB_WORDS * RADIX;

    // Lane 1's maximum terminator must coincide with the physical top.
    if (DUAL_EN && (LANE1_TOP != PE_UNITS_P + 1))
        $fatal(1, "tessera_rsa_montgomerymultiplier: dual lane 1 top stage (%0d) does not land on the physical top stage (%0d)",
               LANE1_TOP, PE_UNITS_P + 1);

    // S_NUM must be odd: otherwise PE_UNITS truncates and omits a result word.
    // Elaboration checks also reject invalid geometry during synthesis.
    if (2*(PE_UNITS+1) + 1 != S_NUM)
        $fatal(1, "tessera_rsa_montgomerymultiplier: S_NUM (%0d) must be odd -- KEY_SIZE/RADIX (%0d/%0d) does not tile the PE chain",
               S_NUM, MODULUS_WIDTH, RADIX);

    // Half-width tiling is an independent constraint.
    if (2*(PE_UNITS_H+1) + 1 != S_NUM_H)
        $fatal(1, "tessera_rsa_montgomerymultiplier: S_NUM_H (%0d) must be odd -- KEY_SIZE/2 / RADIX (%0d/%0d) does not tile the PE chain",
               S_NUM_H, MODULUS_WIDTH_H, RADIX);


    //----------------------------------------------------------------
    // mm
    //----------------------------------------------------------------
    logic [RADIX-1 : 0] a_array[0:PE_UNITS_P+1];
    logic [RADIX-1 : 0] b_array[0:PE_UNITS_P+1];
    logic [RADIX-1 : 0] p_array[0:PE_UNITS_P+1];
    logic [RADIX-1 : 0] m_array[0:PE_UNITS_P];
    logic [RADIX   : 0] c_array[0:PE_UNITS_P+1];
    logic [RADIX-1 : 0] s_array[0:PE_UNITS_P+1];

    logic [RADIX-1 : 0] p_neg_array[0:TWORDS-1];
    logic [RADIX-1 : 0] t_reg[0:TWORDS-1];
    logic [RADIX-1 : 0] t_subtracted_reg[0:TWORDS-1];
    logic [RADIX   : 0] sub_res[0:TWORDS-1];

    logic               sub_b_i[0:TWORDS-1];
    logic               sub_b_o[0:TWORDS-1];
    
    logic   [FULL_REG_SIZE-1 : 0]          a_reg;
    logic   [PB_SIZE-1 : 0]                b_reg;  //extended with zero
    logic   [PB_SIZE-1 : 0]                p_reg;  //extended with zero
    logic   [PB_SIZE-1 : 0]                p_neg_reg; //extended with one
    logic   [RADIX-1:0]               n_prime_reg;
    logic   [RADIX-1:0]               n_prime1_reg;
    logic   [3*S_NUM-1 : 0]           push_reg;
    // One-hot launch token positioned from input geometry on the capture edge.
    logic   [3*S_NUM-1 : 0]           push_tok;
    // Per-word retirement taps, remapped for the shortened sweep.
    logic   [0 : TWORDS-1]            t_push;
    // Clear words outside the new operation's live range to erase prior residue.
    logic   [0 : TWORDS-1]            t_clr;
    logic                             push_reg_zero;
    logic                             push_reg_zero_ff;
    logic                             ready_tok_ff;
    logic                             odd;
    logic   [RADIX-1 : 0]             last_s_reg;
    // Lane 1's top-of-array carry recirculation.  Constant zero unless DUAL_EN.
    logic   [RADIX-1 : 0]             last_s_reg_1;
    logic   [TWORDS*RADIX-1:0]        p_internal;
    logic   [TWORDS*RADIX-1:0]        p_subtracted_internal;

    logic                             nonreducing_reg;
    logic                             reduce_reg;

    // ------------------------------------------------------------------
    // Operand forwarding state. t_reg holds retiring words until the consumer
    // reads them; a counter-indexed a read and fixed b taps need no separate FIFO.
    // ------------------------------------------------------------------
    logic                             fwd_a_reg;
    logic                             fwd_b_reg;
    logic                             fwd_b_live;
    // Latched geometry select, stable throughout the sweep.
    logic                             half_reg;

    // ------------------------------------------------------------------
    // Runtime geometry. TOP_STAGE = (S_NUM-1)/2 determines the sum-chain
    // terminator, retirement taps and final conditional-subtract borrow tap.
    // ------------------------------------------------------------------
    localparam int TOP_STAGE_F  = PE_UNITS + 1;          // full-width terminator
    localparam int TOPS_W       = $clog2(PE_UNITS_P + 2);
    logic [TOPS_W-1:0]   top_stage_cur;
    logic [TOPS_W-1:0]   top_stage_in;
    logic [7:0]          geom_reg;
    logic [TOPS_W:0]     tap_base;                       // 2*top_stage_cur
    // Zero geom selects the default full/half decode.
    assign top_stage_cur = (geom_reg != 8'd0) ? TOPS_W'(geom_reg)
                         : (half_reg ? TOPS_W'(TOP_STAGE_H) : TOPS_W'(TOP_STAGE_F));
    assign top_stage_in  = (geom_i != 8'd0) ? TOPS_W'(geom_i)
                         : ((half_i | (DUAL_EN & dual_i)) ? TOPS_W'(TOP_STAGE_H)
                                                          : TOPS_W'(TOP_STAGE_F));
    assign tap_base      = {top_stage_cur, 1'b0};
    // Lane 1 has its own tap base: default half-width, independent of lane 0's
    // full/half select. A nonzero geom supplies the per-lane top stage.
    logic [TOPS_W-1:0]   top_stage_1_rel;
    logic [TOPS_W-1:0]   top_stage_1_rel_in;
    logic [TOPS_W:0]     tap_base_1;
    logic [TOPS_W:0]     tap_base_1_in;
    assign top_stage_1_rel    = (geom_reg != 8'd0) ? TOPS_W'(geom_reg) : TOPS_W'(TOP_STAGE_H);
    assign top_stage_1_rel_in = (geom_i   != 8'd0) ? TOPS_W'(geom_i)   : TOPS_W'(TOP_STAGE_H);
    assign tap_base_1         = {top_stage_1_rel, 1'b0};
    assign tap_base_1_in      = {top_stage_1_rel_in, 1'b0};
    // The start wavefront needs dual_i on the launch edge, before dual_reg updates.
    logic                             dual_reg;
    logic                             dual_sel;
    logic                             reduce_q1;
    logic   [1:0]                     mm_nout;
    logic   [LOW_CNT_WIDTH-1:0]       a_idx;
    logic   [RADIX-1 : 0]             t_fwd_word;
    logic   [RADIX-1 : 0]             t_fwd_word1;
    logic   [RADIX-1 : 0]             a_array1_in;
    logic   [PB_SIZE-1:0]             t_flat;
    // Operand words, excluding the guard word, for forwarding masks.
    localparam int MOD_WORDS = MODULUS_WIDTH / RADIX;
    localparam int MOD_WORDS_H = MODULUS_WIDTH_H / RADIX;

    // Disable held forwarding controls for pipeline diagnostics while retaining
    // the start wavefront and b double buffer.
`ifdef RSA_MM_NO_FWD
    localparam bit MM_NO_FWD = 1'b1;
`else
    localparam bit MM_NO_FWD = 1'b0;
`endif

    // Minimum interval 2*S_NUM+2 consumes word 0 as soon as it is readable.
    // If retirement is retimed, add margin with RSA_MM_II_EXTRA; it must be
    // even to preserve the shared odd phase.
`ifdef RSA_MM_II_EXTRA
    localparam int MM_II = 2*S_NUM + 2 + `RSA_MM_II_EXTRA;
`else
    localparam int MM_II = 2*S_NUM + 2;
`endif
    localparam int ACC_CNT_W = $clog2(MM_II + 1) + 1;
    // Half-width interval uses the same extra margin and parity.
    localparam int MM_II_H = 2*S_NUM_H + 2 + (MM_II - (2*S_NUM + 2));

    // ------------------------------------------------------------------
    // Geometry identities avoid separate lookup tables:
    //     MOD_WORDS = MODULUS_WIDTH/RADIX = 2*TOP_STAGE     = tap_base
    //     S_NUM     = MOD_WORDS + 1                         = tap_base + 1
    //     MM_II     = 2*S_NUM + 2                           = 2*tap_base + 4
    //     2*NSTAGE - 2 (the last_s_reg clear tap) = 2*TOP_STAGE = tap_base
    // ------------------------------------------------------------------
    logic [TOPS_W:0]      s_num_cur;
    logic [ACC_CNT_W-1:0] mm_ii_cur;
    logic [TOPS_W:0]      tap_base_in;   // input-side, for the push token
    assign s_num_cur   = tap_base + (TOPS_W+1)'(1);
    assign mm_ii_cur   = ACC_CNT_W'(2*tap_base) + ACC_CNT_W'(4 + (MM_II - (2*S_NUM + 2)));
    assign tap_base_in = {top_stage_in, 1'b0};

    // Validate whole-word geometry and the tap-base identities.
    if (MOD_WORDS * RADIX != MODULUS_WIDTH)
        $fatal(1, "tessera_rsa_montgomerymultiplier: MODULUS_WIDTH (%0d) must be a whole number of RADIX-%0d words for the word-granular result mask",
               MODULUS_WIDTH, RADIX);
    if (2*TOP_STAGE_F != MOD_WORDS)
        $fatal(1, "tessera_rsa_montgomerymultiplier: tap_base identity broken -- 2*TOP_STAGE_F (%0d) != MOD_WORDS (%0d)",
               2*TOP_STAGE_F, MOD_WORDS);
    if (2*TOP_STAGE_H != MOD_WORDS_H)
        $fatal(1, "tessera_rsa_montgomerymultiplier: tap_base identity broken in half mode -- 2*TOP_STAGE_H (%0d) != MOD_WORDS_H (%0d)",
               2*TOP_STAGE_H, MOD_WORDS_H);
    if (MOD_WORDS_H * RADIX != MODULUS_WIDTH_H)
        $fatal(1, "tessera_rsa_montgomerymultiplier: MODULUS_WIDTH_H (%0d) must be a whole number of RADIX-%0d words",
               MODULUS_WIDTH_H, RADIX);

    // Odd intervals misalign the consumer with the global PE phase and corrupt
    // overlapped work. This also constrains RSA_MM_II_EXTRA.
    if (MM_II % 2 != 0)
        $fatal(1, "tessera_rsa_montgomerymultiplier: MM_II (%0d) must be EVEN -- check RSA_MM_II_EXTRA", MM_II);
    logic   [ACC_CNT_W-1:0]           acc_cnt;
    logic   [RADIX-1 : 0]             low_tap;
    logic   [FULL_REG_SIZE-1:0]       low_reg;
    logic   [LOW_CNT_WIDTH-1:0]       low_cnt;
    
    //----------------------------------------------------------------
    // Pipelined stage control. Stage j reads s_array[j] from stage j+1:
    // sums flow down while a words flow up, one stage per two cycles.
    // A delayed start clears each stage without disturbing the older drain;
    // first-step sum masking prevents reuse of its neighbor's old partial sum.
    // Without pipelining, start is broadcast and sums use s_eff directly.
    //----------------------------------------------------------------
    localparam int NSTAGE = PE_UNITS + 2;
    // Pipelining is enabled by default; the serialized fallback is a reference mode.
`ifdef RSA_MM_NO_PIPELINE
    localparam bit MM_PIPELINE = 1'b0;
`else
    localparam bit MM_PIPELINE = 1'b1;
`endif

    logic [2*NSTAGE_P-1:0]  start_pipe;
    logic [NSTAGE_P-1:0]    stage_start;
    // stage_start clears registers; stage_first marks the later sum-zero phase.
    // Keep them distinct: b selection is registered, but the s_in mux is combinational.
    logic [NSTAGE_P-1:0]    stage_first;
    logic [RADIX-1:0]     stage_s_in[0:NSTAGE_P-1];

    // ------------------------------------------------------------------
    // Effective sum-chain taps. Each lane's current terminator reads its
    // recirculated carry instead of the next physical stage's sum.
    // Stage inputs, retirement and conditional subtraction all use s_eff.
    // Taps above the live range are never retired, isolating inactive stages.
    // ------------------------------------------------------------------
    logic [RADIX-1:0]     s_eff[0:PE_UNITS_P+1];

    // Lane 1's absolute terminator is LANE1_S0 plus its relative top stage.
    // Outside dual mode, park on LANE1_TOP to keep the c_array index in range.
    logic [TOPS_W:0]      top_stage_1_cur;
    assign top_stage_1_cur = dual_reg
                           ? ((TOPS_W+1)'(LANE1_S0) + (TOPS_W+1)'(top_stage_1_rel))
                           : (TOPS_W+1)'(LANE1_TOP);

    genvar se;
    generate
        for (se = 0; se <= PE_UNITS_P+1; se++) begin : gen_s_eff
            if (DUAL_EN) begin : gen_s_eff_dual
                assign s_eff[se] = (top_stage_cur == TOPS_W'(se)) ? last_s_reg
                                 : (dual_reg && (top_stage_1_cur == (TOPS_W+1)'(se))) ? last_s_reg_1
                                 : s_array[se];
            end
            else begin : gen_s_eff_single
                assign s_eff[se] = (top_stage_cur == TOPS_W'(se)) ? last_s_reg : s_array[se];
            end
        end
    endgenerate

    always_ff @(posedge clk) begin
        if (~reset_n | zeroize)
            start_pipe <= '0;
        else
            start_pipe <= {start_pipe[2*NSTAGE_P-2:0], start_i};
    end

    genvar gs;
    generate
        for (gs = 0; gs < NSTAGE_P; gs++) begin : gen_stage_ctrl
            // Both lanes launch together, so dual wavefront offsets are lane-relative.
            localparam int JR = gs - LANE1_S0;
            if (gs == 0) begin : gen_stage0
                assign stage_start[gs] = start_i;
            end
            else if (DUAL_EN && (gs >= LANE1_S0)) begin : gen_stagen_dual
                assign stage_start[gs] = dual_sel
                                       ? ((JR == 0) ? start_i
                                                    : (MM_PIPELINE ? start_pipe[(JR > 0 ? 2*JR-2 : 0)] : start_i))
                                       : (MM_PIPELINE ? start_pipe[2*gs-2] : start_i);
            end
            else begin : gen_stagen
                // Clear at 2*gs-1, before the operand arrives at 2*gs; a later
                // pulse would discard its even phase. start_pipe[0] delays one cycle.
                assign stage_start[gs] = MM_PIPELINE ? start_pipe[2*gs-2] : start_i;
            end
            if (gs == 0) begin : gen_first0
                assign stage_first[gs] = start_pipe[0];
            end
            else if (DUAL_EN && (gs >= LANE1_S0)) begin : gen_firstn_dual
                assign stage_first[gs] = dual_sel ? start_pipe[(JR > 0 ? 2*JR : 0)]
                                                  : start_pipe[2*gs];
            end
            else begin : gen_firstn
                assign stage_first[gs] = start_pipe[2*gs];
            end
            assign stage_s_in[gs] = (MM_PIPELINE & stage_first[gs]) ? {RADIX{1'b0}}
                                                                    : s_eff[gs];
        end
    endgenerate

    // Per-lane quotient constants, computed on operand load.
    logic [RADIX-1:0]   bn0_reg;
    logic [RADIX-1:0]   bn1_reg;

    tessera_rsa_pe_first #(
        .RADIX(RADIX)
        )
        first_box
        (
        .clk(clk),
        .reset_n(reset_n),
        .start_in(stage_start[0]),
        .zeroize(zeroize),
        .a_in(a_array[0]),
        .b_in(b_array[0]),
        .p_in(p_array[0]),
        .s_in(stage_s_in[0]),
        .n_prime_in(n_prime_reg),
        .bn0_in(bn0_reg),
        .odd(odd),
        // Local multipliers; explicit unused ports avoid TFIPC warnings.
        .ext_ab_in('0),
        .ext_pm_in('0),
        .mul_a_o(),
        .mul_m_o(),

        .a_out(a_array[1]),
        .m_out(m_array[0]),
        .c_out(c_array[0]),
        .low_out(low_tap)
        );

    genvar i;
    generate 
        for (i=0; i < PE_UNITS_P; i++) begin : gen_PE //PE general boxes
            // This slot needs both a middle PE and a quotient-generating head,
            // sharing full-width multipliers; see tessera_rsa_pe_lane1_boundary.sv.
            // In dual mode its middle s_out is unread: s_eff terminates lane 0
            // at last_s_reg, isolating the boundary.
            localparam bit LANE1_BOUNDARY = DUAL_EN && (i == LANE1_S0-1);

            if (LANE1_BOUNDARY) begin : gen_lane1_head
                tessera_rsa_pe_lane1_boundary #(
                    .RADIX(RADIX)
                    )
                    boundary_box
                    (
                    .clk(clk),
                    .reset_n(reset_n),
                    .start_in(stage_start[i+1]),
                    .zeroize(zeroize),
                    .dual_sel(dual_sel),

                    .b_in(b_array[i+1]),
                    .p_in(p_array[i+1]),
                    .s_in(stage_s_in[i+1]),
                    .odd(odd),

                    .a_in(a_array[i+1]),
                    .m_in(m_array[i]),
                    .c_in(c_array[i]),

                    .a1_in(a_array1_in),
                    .n_prime1_in(n_prime1_reg),
                    .bn1_in(bn1_reg),

                    .a_out(a_array[i+2]),
                    .m_out(m_array[i+1]),
                    .c_out(c_array[i+1]),
                    .s_out(s_array[i])
                    );
            end
            else begin : gen_pe_out
                tessera_rsa_pe #(
                    .RADIX(RADIX)
                    )
                    box_i
                    (
                    .clk(clk),
                    .reset_n(reset_n),
                    .start_in(stage_start[i+1]),
                    .zeroize(zeroize),
                    .a_in(a_array[i+1]),
                    .b_in(b_array[i+1]),
                    .p_in(p_array[i+1]),
                    .m_in(m_array[i]),
                    .s_in(stage_s_in[i+1]),
                    .c_in(c_array[i]),
                    .odd(odd),
                    // Local multipliers; explicit tie-offs avoid TFIPC warnings.
                    .ext_ab_in('0),
                    .ext_pm_in('0),

                    .a_out(a_array[i+2]),
                    .m_out(m_array[i+1]),
                    .s_out(s_array[i]),
                    .c_out(c_array[i+1])
                    );
            end
        end
    endgenerate

    tessera_rsa_pe_final #(
        .RADIX(RADIX)
        )
        final_box
        (
        .clk(clk),
        .reset_n(reset_n),
        .start_in(stage_start[PE_UNITS_P+1]),
        .zeroize(zeroize),
        .a_in(a_array[PE_UNITS_P+1]),
        .b_in(b_array[PE_UNITS_P+1]),
        .p_in(p_array[PE_UNITS_P+1]),
        .m_in(m_array[PE_UNITS_P]),
        .s_in(stage_s_in[PE_UNITS_P+1]),
        .c_in(c_array[PE_UNITS_P]),
        .odd(odd),

        .s_out(s_array[PE_UNITS_P]),
        .c_out(c_array[PE_UNITS_P+1])
        );
        
    // The physical top belongs to lane 1 in dual mode; s_eff terminates lane 0 separately.
    assign s_array[PE_UNITS_P+1] = (DUAL_EN && dual_reg) ? last_s_reg_1 : last_s_reg;
    
    // Carry recirculation acts as a virtual stage above the terminator.
    // Clear on its wavefront, not start_i, to preserve the older drain's carry.
    // The top PE initially uses its cleared s_out, then stage_s_in forces zero
    // until this register has been cleared for the new multiply.
    always_ff @(posedge clk) begin
        if (~reset_n)
            last_s_reg <= 'b0;
        else if (zeroize)
            last_s_reg <= 'b0;
        else if (MM_PIPELINE ? start_pipe[tap_base] : start_i)
            last_s_reg <= 'b0;
        else
            last_s_reg <= c_array[top_stage_cur][RADIX-1:0];
    end

    // Lane 1 recirculates carry from its own runtime terminator.
    generate
        if (DUAL_EN) begin : gen_last_s_1
            always_ff @(posedge clk) begin
                if (~reset_n)
                    last_s_reg_1 <= 'b0;
                else if (zeroize)
                    last_s_reg_1 <= 'b0;
                // Clearing uses a lane-relative offset from the shared launch.
                else if (MM_PIPELINE ? start_pipe[tap_base_1] : start_i)
                    last_s_reg_1 <= 'b0;
                else
                    last_s_reg_1 <= c_array[top_stage_1_cur][RADIX-1:0];
            end
        end
        else begin : gen_no_last_s_1
            assign last_s_reg_1 = '0;
        end
    endgenerate

    // Preserve the global odd phase while an older multiply drains.
    // Only an idle launch reinitializes it; even launch intervals align consumers.
    always_ff @(posedge clk) begin
        if (~reset_n)
            odd <= 0;
        else if (zeroize)
            odd <= 0;
        else if (start_i & (MM_PIPELINE ? push_reg_zero : 1'b1))
            odd <= 1'b1;
        else
            odd <= ~odd;
    end

    always_ff @(posedge clk) begin
        if (zeroize) begin
            a_reg <= 'b0;
            b_reg <= 'b0;
            p_reg <= 'b0;
            n_prime_reg <= 'b0;
            n_prime1_reg <= 'b0;
        end else if (start_i) begin
            // a_reg packs {a1, guard, a0} in S_NUM words. b/p place lane 1
            // at LANE1_W0. Zero guards terminate both operand streams.
            if (DUAL_EN && dual_i) begin
                a_reg <= FULL_REG_SIZE'({opa1_i, {RADIX{1'b0}}, opa_i[MODULUS_WIDTH_H-1:0]});
                b_reg <= (MM_PIPELINE & fwd_b_i) ? t_flat
                                                 : PB_SIZE'({opb1_i, {(LANE1_W0-MOD_WORDS_H)*RADIX{1'b0}}, opb_i[MODULUS_WIDTH_H-1:0]});
                p_reg <= PB_SIZE'({n1_i, {(LANE1_W0-MOD_WORDS_H)*RADIX{1'b0}}, n_i[MODULUS_WIDTH_H-1:0]});
            end
            else begin
                a_reg <= opa_i;
                // Forward through b_reg so b_reg_prev preserves the older operand.
                // Load available retirement words now and track later words below.
                b_reg <= (MM_PIPELINE & fwd_b_i) ? t_flat : opb_i;
                p_reg <= n_i;
            end
            n_prime_reg  <= nonreducing_i ? {RADIX{1'b0}} : n_prime_i;
            n_prime1_reg <= n_prime1_i;
        end else begin
            if (odd) begin
                a_reg[FULL_REG_SIZE-RADIX-1 : 0] <= a_reg[FULL_REG_SIZE-1 : RADIX];
                a_reg[FULL_REG_SIZE-1 : FULL_REG_SIZE-RADIX] <= 'b0; //Shift 
            end 
            // Track retiring words only until the producer's ready_o.
            // Afterward t_reg is reused by this multiply; continued tracking
            // would overwrite its b operand while stages still consume it.
            if (fwd_b_reg & fwd_b_live)
                b_reg <= t_flat;
        end

        if (~reset_n) begin
            a_reg <= 'b0;
            b_reg <= 'b0;
            p_reg <= 'b0;
            n_prime_reg <= 'b0;
            n_prime1_reg <= 'b0;
        end
    end

    // ------------------------------------------------------------------
    // Precompute bn0 = (b0*n_prime) mod 2^RADIX for the parallel quotient
    // products in tessera_rsa_pe_first. Use b_reg's load source, not b_reg itself,
    // so the constant is ready for the first compute cycle.
    // Each head uses a fixed b word (0 or LANE1_W0), already retired at a
    // forwarded launch; later top-ups leave that word unchanged.
    // Non-reducing mode forces both n_prime and bn0 to zero.
    // ------------------------------------------------------------------
    logic [RADIX-1:0]   b0_next;
    logic [RADIX-1:0]   bn0_next;
    logic [RADIX-1:0]   np_next;

    assign np_next = nonreducing_i ? {RADIX{1'b0}} : n_prime_i;
    // Lane 0's low b word has the same position in single and dual packing.
    assign b0_next = (MM_PIPELINE & fwd_b_i) ? t_flat[RADIX-1:0]
                                             : opb_i[RADIX-1:0];

    // Only the low RADIX bits contribute to the quotient constant.
    tessera_rsa_mult_low #(.RADIX(RADIX)) BN0_MULT (
        .A(b0_next),
        .B(np_next),
        .P(bn0_next)
    );

    generate
        if (DUAL_EN) begin : gen_bn1
            logic [RADIX-1:0]   b1_next;
            logic [RADIX-1:0]   bn1_next;

            // Lane 1 uses its own low word; lockstep retirement preserves availability.
            assign b1_next = (MM_PIPELINE & fwd_b_i)
                           ? t_flat[LANE1_W0*RADIX +: RADIX]
                           : opb1_i[RADIX-1:0];

            tessera_rsa_mult_low #(.RADIX(RADIX)) BN1_MULT (
                .A(b1_next),
                .B(n_prime1_i),
                .P(bn1_next)
            );

            always_ff @(posedge clk) begin
                if (!reset_n || zeroize)
                    bn1_reg <= '0;
                else if (start_i)
                    bn1_reg <= bn1_next;
            end
        end else begin : gen_no_bn1
            assign bn1_reg = '0;
        end
    endgenerate

    always_ff @(posedge clk) begin
        if (!reset_n || zeroize)
            bn0_reg <= '0;
        else if (start_i)
            bn0_reg <= bn0_next;
    end

    // ------------------------------------------------------------------
    // Launch attributes, forwarding index and accept handshake.
    // ------------------------------------------------------------------
    always_ff @(posedge clk) begin
        if (~reset_n | zeroize) begin
            fwd_a_reg <= 1'b0;
            fwd_b_reg <= 1'b0;
            half_reg  <= 1'b0;
            geom_reg  <= 8'd0;
            dual_reg  <= 1'b0;
        end
        else if (start_i) begin
            fwd_a_reg <= MM_PIPELINE & fwd_a_i & ~MM_NO_FWD;
            fwd_b_reg <= MM_PIPELINE & fwd_b_i & ~MM_NO_FWD;
            // Dual mode defaults to half-width geometry for each lane.
            half_reg  <= half_i | (DUAL_EN & dual_i);
            geom_reg  <= geom_i;
            dual_reg  <= DUAL_EN & dual_i;
        end
    end

    // Select lane 1's start wavefront on the launch edge, before dual_reg updates.
    assign dual_sel = DUAL_EN ? (start_i ? dual_i : dual_reg) : 1'b0;

    // Track until the producer retires; simultaneous launch takes priority.
    always_ff @(posedge clk) begin
        if (~reset_n | zeroize)
            fwd_b_live <= 1'b0;
        else if (start_i)
            fwd_b_live <= MM_PIPELINE & fwd_b_i & ~MM_NO_FWD;
        else if (ready_o)
            fwd_b_live <= 1'b0;
    end

    // Match a_reg's one-word-per-two-cycles cadence.
    always_ff @(posedge clk) begin
        if (~reset_n | zeroize)
            a_idx <= '0;
        else if (start_i)
            a_idx <= '0;
        else if (odd & (a_idx != LOW_CNT_WIDTH'(2*(PE_UNITS+1))))
            a_idx <= a_idx + 1'b1;
    end

    // A bounded mux avoids out-of-range a_idx encodings and VCS SIOB warnings.
    // Exclude guard/inactive words to match the zero-extended operand ports:
    // an unreduced t_reg guard word need not be zero, while p_o truncates it.
    always_comb begin
        t_fwd_word = '0;
        for (int q = 0; q < MOD_WORDS; q++)
            if ((a_idx == LOW_CNT_WIDTH'(q)) & (q < int'(tap_base)))
                t_fwd_word = t_reg[q];
    end

    // Apply the same forwarding bound within lane 1's word range.
    always_comb begin
        t_fwd_word1 = '0;
        if (DUAL_EN)
            for (int q = 0; q < MOD_WORDS_H; q++)
                if ((a_idx == LOW_CNT_WIDTH'(q)) & (q < int'(tap_base_1)))
                    t_fwd_word1 = t_reg[LANE1_W0 + q];
    end

    // Preserve p_internal's word ordering and zero-extend each live operand.
    // Dual forwarding must reproduce b_reg's packing, including lane 1 at
    // LANE1_W0; a single half-width mask would erase lane 1's operand.
    always_comb begin
        t_flat = '0;
        for (int q = 0; q < MOD_WORDS; q++)
            t_flat[q*RADIX +: RADIX] = (q >= int'(tap_base)) ? {RADIX{1'b0}} : t_reg[q];
        if (DUAL_EN && dual_reg)
            for (int q = 0; q < MOD_WORDS_H; q++)
                t_flat[(LANE1_W0 + q)*RADIX +: RADIX] = (q >= int'(tap_base_1))
                                                      ? {RADIX{1'b0}} : t_reg[LANE1_W0 + q];
    end

    always_ff @(posedge clk) begin
        if (~reset_n | zeroize)
            acc_cnt <= '0;
        else if (start_i)
            acc_cnt <= ACC_CNT_W'(1);
        else if ((acc_cnt != '0) & (acc_cnt < ACC_CNT_W'(MM_II)))
            acc_cnt <= acc_cnt + 1'b1;
    end

    assign accept_o = MM_PIPELINE ? (acc_cnt >= mm_ii_cur)
                                  : ready_o;

    // ------------------------------------------------------------------
    // Double-buffer b because upper stages still read the outgoing operand
    // after a new launch. Each stage switches when its start wavefront arrives.
    // a_reg is already consumed by then; p_reg is shared because the modulus
    // must remain constant across overlapped multiplies.
    // ------------------------------------------------------------------
    logic [PB_SIZE-1 : 0] b_stage [0 : PE_UNITS_P+1];

    generate
        if (MM_PIPELINE) begin : gen_b_dbuf
            logic [PB_SIZE-1 : 0] b_reg_prev;
            // b_sel_q[k] == 1 -> stage k is on the newest operand (b_reg).
            logic [PE_UNITS_P+1 : 0]          b_sel_q;

            always_ff @(posedge clk) begin
                if (!reset_n || zeroize) begin
                    b_reg_prev <= '0;
                    b_sel_q    <= '0;
                end else begin
                    if (start_i)
                        b_reg_prev <= b_reg;
                    // Both active heads take the new operand immediately.
                    // Other stages retain the previous operand until their wavefront.
                    if (start_i)
                        b_sel_q <= (DUAL_EN & dual_i)
                                 ? (((PE_UNITS_P+2)'(1) << LANE1_S0) | (PE_UNITS_P+2)'(1))
                                 : {{(PE_UNITS_P+1){1'b0}}, 1'b1};
                    else
                        for (int k = 1; k <= PE_UNITS_P+1; k++)
                            if (stage_start[k])
                                b_sel_q[k] <= 1'b1;
                end
            end

            for (genvar k2 = 0; k2 <= PE_UNITS_P+1; k2++) begin : gen_b_mux
                assign b_stage[k2] = b_sel_q[k2] ? b_reg : b_reg_prev;
            end
        end else begin : gen_b_single
            for (genvar k2 = 0; k2 <= PE_UNITS_P+1; k2++) begin : gen_b_flat
                assign b_stage[k2] = b_reg;
            end
        end
    endgenerate

    assign a_array[0] = fwd_a_reg ? t_fwd_word : a_reg[RADIX-1 : 0];
    // With {a1, guard, a0} packing, this fixed tap advances in lockstep with lane 0.
    assign a_array1_in = fwd_a_reg ? t_fwd_word1
                                   : a_reg[(MOD_WORDS_H+1)*RADIX +: RADIX];
    assign b_array[0] = b_stage[0][RADIX-1 : 0];
    assign p_array[0] = p_reg[RADIX-1 : 0];

    genvar j;
    generate 
        for (j=1; j < PE_UNITS_P+2; j++) begin : gen_b_p_array
            if (DUAL_EN && (j == LANE1_S0)) begin : gen_lane1_head_bp
                // A head uses its fixed low word rather than the middle PE's odd/even taps.
                assign b_array[j] = dual_sel ? b_stage[j][LANE1_W0*RADIX +: RADIX]
                                             : (odd ? b_stage[j][(2*j+1)*RADIX-1 : (2*j)*RADIX] : b_stage[j][(2*j)*RADIX-1 : (2*j-1)*RADIX]);
                assign p_array[j] = dual_sel ? p_reg[LANE1_W0*RADIX +: RADIX]
                                             : (odd ? p_reg[(2*j+1)*RADIX-1 : (2*j)*RADIX] : p_reg[(2*j)*RADIX-1 : (2*j-1)*RADIX]);
            end
            else begin : gen_bp_generic
                // LANE1_W0 == 2*NSTAGE_H keeps these taps lane-relative in dual mode.
                assign b_array[j] = odd ? b_stage[j][(2*j+1)*RADIX-1 : (2*j)*RADIX] : b_stage[j][(2*j)*RADIX-1 : (2*j-1)*RADIX];
                assign p_array[j] = odd ? p_reg[(2*j+1)*RADIX-1 : (2*j)*RADIX] : p_reg[(2*j)*RADIX-1 : (2*j-1)*RADIX];
            end
        end
    endgenerate


    assign p_neg_reg = ~p_reg;
    
    genvar i0;
    generate 
        for (i0=0; i0 < TWORDS; i0++) begin : gen_n_neg_array
            assign p_neg_array[i0] = p_neg_reg[i0*RADIX +: RADIX];
        end
    endgenerate

    // Position from input geometry because launch also captures the held geometry.
    // 3*S_NUM_in-1 = 3*tap_base_in+2; widen to int to avoid truncating the shift.
    assign push_tok = (3*S_NUM)'(1) << (3*int'(tap_base_in) + 2);

    // Each live word retires on its geometry-relative tap. Dual mode has two
    // live ranges, separated by the unretired GAP_W; both use the same token.
    // Clear decisions use the launching mode, not the still-held draining mode.
    logic start_half;
    logic start_dual;
    assign start_half = start_i & (half_i | (DUAL_EN & dual_i));
    assign start_dual = start_i & (DUAL_EN & dual_i);

    genvar tp;
    generate
        for (tp = 0; tp < TWORDS; tp++) begin : gen_t_push
            localparam bit IN_L0   = (tp <= 2*(PE_UNITS_H+1));
            localparam bit IN_L1   = DUAL_EN && (tp >= LANE1_W0)
                                            && (tp <= LANE1_W0 + 2*(PE_UNITS_H+1));
            localparam int L1_REL  = IN_L1 ? (tp - LANE1_W0) : 0;
            localparam bit IN_FULL = (tp <= 2*(PE_UNITS+1));

            // Runtime bounds guard variable tap indices; IN_FULL separately
            // limits the words lane 0 can reach in any geometry.
            if (IN_L1) begin : gen_tp_l1
                // Use lane 1's relative tap in dual mode; otherwise use lane 0's
                // geometry where reachable. Bounds guard both variable indices.
                assign t_push[tp] = dual_reg
                        ? ((L1_REL <= int'(tap_base_1))
                              ? push_reg[tap_base_1 - (TOPS_W+1)'(L1_REL)] : 1'b0)
                        : (IN_FULL && (tp <= int'(tap_base)))
                              ? push_reg[tap_base - (TOPS_W+1)'(tp)] : 1'b0;
                // Erase words outside the new lane-1 live range on a shortened launch.
                assign t_clr[tp]  = start_dual ? (L1_REL > int'(tap_base_1_in))
                                  : IN_FULL    ? (start_i & (tp > int'(tap_base_in)))
                                               : start_half;
            end
            else if (IN_FULL) begin : gen_tp_live
                assign t_push[tp] = (tp <= int'(tap_base))
                              ? push_reg[tap_base - (TOPS_W+1)'(tp)] : 1'b0;
                // Erase residue left by a wider operation.
                assign t_clr[tp]  = start_i & (tp > int'(tap_base_in));
            end
            else begin : gen_tp_none
                // Written in no lane-0 geometry at all.
                assign t_push[tp] = 1'b0;
                assign t_clr[tp]  = 1'b0;
            end
        end
    endgenerate

    genvar t0;
    generate 
        for (t0=0; t0 < TWORDS; t0++) begin : gen_sub_t
            // Resolve word 0 at generate time to avoid elaborating sub_b_o[-1].
            // Dual lanes subtract independently: cut the ripple at LANE1_W0
            // and reseed the two's-complement +1.
            if (t0 == 0)
                always_comb sub_b_i[t0] = 1;
            else if (DUAL_EN && (t0 == LANE1_W0))
                always_comb sub_b_i[t0] = dual_reg ? 1'b1 : sub_b_o[t0 - 1];
            else
                always_comb sub_b_i[t0] = sub_b_o[t0 - 1];

            always_comb begin
                // Intentional transparent latch: retain each word's borrow
                // between retirement taps, which fire on different cycles.
                // Reset/zeroize must erase this secret-derived state even
                // when clearing push_reg prevents any further tap from firing.
                if (~reset_n | zeroize)
                    sub_res[t0] = 0;
                else if (t_push[t0])
                    sub_res[t0] = {1'b0, s_eff[t0 >> 1]} + p_neg_array[t0] + sub_b_i[t0];
                // Clear inactive residue without disturbing the live borrow chain;
                // final-borrow taps remain below the cleared words in each lane.
                else if (t_clr[t0])
                    sub_res[t0] = 0;

                sub_b_o[t0] = sub_res[t0][RADIX];
            end
        end
    endgenerate

    genvar t;
    generate 
        for (t=0; t < TWORDS; t++) begin : gen_t_reg
            always_ff @(posedge clk) begin
                if (~reset_n) begin
                    t_reg[t] <= 'b0;
                    t_subtracted_reg[t] <= 'b0;
                end
                else if (zeroize) begin
                    t_reg[t] <= 'b0;
                    t_subtracted_reg[t] <= 'b0;
                end
                else if (t_push[t]) begin
                    t_reg[t] <= s_eff[t >> 1];
                    t_subtracted_reg[t] <= sub_res[t][RADIX-1 : 0];
                end
                // A shorter operation will not overwrite upper secret-derived
                // words. Read masking is not erasure: clear them on launch.
                // Live retirement retains priority over the inactive-word clear.
                else if (t_clr[t]) begin
                    t_reg[t] <= 'b0;
                    t_subtracted_reg[t] <= 'b0;
                end
                else begin
                    t_reg[t] <= t_reg[t];
                    t_subtracted_reg[t] <= t_subtracted_reg[t];
                end
            end
        end
    endgenerate
    
    genvar k;
    generate 
        for (k=0; k < TWORDS; k++) begin : gen_p_o
            assign p_internal[k*RADIX +: RADIX] = t_reg[k];
            assign p_subtracted_internal[k*RADIX +: RADIX] = t_subtracted_reg[k];
        end
    endgenerate

    // Select the live terminator's final borrow; inactive upper taps may be stale.
    logic                         sub_borrow_final;
    logic [MODULUS_WIDTH-1:0]     p_full;

    assign sub_borrow_final = sub_b_o[tap_base];

    assign p_full = (reduce_reg & sub_borrow_final) ? p_subtracted_internal[MODULUS_WIDTH-1:0]
                                                    : p_internal[MODULUS_WIDTH-1:0];

    // Zero-extend the runtime-width result: tessera_rsa_modexp feeds p_o back as an
    // operand, so guard and inactive words must not enter the next multiply.
    logic [MODULUS_WIDTH-1:0] p_live_mask;
    always_comb begin
        p_live_mask = '0;
        for (int q = 0; q < MOD_WORDS; q++)
            if (q < int'(tap_base))
                p_live_mask[q*RADIX +: RADIX] = {RADIX{1'b1}};
    end
    assign p_o = p_full & p_live_mask;

    // ------------------------------------------------------------------
    // Lane 1 uses its own final borrow and modulus. Its result begins at
    // LANE1_W0, not at the high half of p_full.
    // ------------------------------------------------------------------
    generate
        if (DUAL_EN) begin : gen_p1
            logic                        sub_borrow_final_1;
            logic [MODULUS_WIDTH_H-1:0]  p1_full;
            logic [MODULUS_WIDTH_H-1:0]  p1_live_mask_c;   // word-granular, lane-1 width

            // Use lane 1's tap base, not lane 0's possibly full-width geometry.
            assign sub_borrow_final_1 =
                sub_b_o[LANE1_W0 + int'(tap_base_1)];
            assign p1_full = (reduce_reg & sub_borrow_final_1)
                           ? p_subtracted_internal[LANE1_W0*RADIX +: MODULUS_WIDTH_H]
                           : p_internal[LANE1_W0*RADIX +: MODULUS_WIDTH_H];

            // Mask the fixed lane-1 aperture to its runtime live width.
            always_comb begin
                p1_live_mask_c = '0;
                for (int q = 0; q < MOD_WORDS_H; q++)
                    if ((TOPS_W+1)'(q) < tap_base_1)
                        p1_live_mask_c[q*RADIX +: RADIX] = {RADIX{1'b1}};
            end
            assign p1_o = {{(MODULUS_WIDTH-MODULUS_WIDTH_H){1'b0}}, (p1_full & p1_live_mask_c)};
        end
        else begin : gen_no_p1
            assign p1_o = '0;
        end
    endgenerate

    // Capture one non-reducing low word per two-cycle step, on odd == 0,
    // when the first PE's res_1 holds the retired word.
    always_ff @(posedge clk) begin
        if (~reset_n | zeroize) begin
            nonreducing_reg <= 1'b0;
            low_reg         <= '0;
            low_cnt         <= '0;
        end
        else if (start_i) begin
            nonreducing_reg <= nonreducing_i;
            low_reg         <= '0;
            low_cnt         <= '0;
        end
        else if (nonreducing_reg & ~odd & (low_cnt != LOW_CNT_WIDTH'(s_num_cur))) begin
            low_reg[low_cnt*RADIX +: RADIX] <= low_tap;
            low_cnt                         <= low_cnt + 1'b1;
        end
    end

    // ------------------------------------------------------------------
    // Queue reduce_i for the at-most-two in-flight multiplies; a younger
    // launch must not change the older result's final-subtraction selection.
    // Pop on ready_o so p_o retains the retiring mode when the FSM samples it.
    // nonreducing remains a launch latch: MUL does not overlap and needs it
    // during low-word capture, not just retirement.
    // ------------------------------------------------------------------
    always_ff @(posedge clk) begin
        if (~reset_n | zeroize) begin
            reduce_reg <= 1'b1;
            reduce_q1  <= 1'b1;
            mm_nout    <= 2'd0;
        end
        else if (!MM_PIPELINE) begin
            if (start_i)
                reduce_reg <= reduce_i;
        end
        else begin
            case ({start_i, ready_o})
                2'b10: begin
                    mm_nout <= mm_nout + 2'd1;
                    if (mm_nout == 2'd0) reduce_reg <= reduce_i;
                    else                 reduce_q1  <= reduce_i;
                end
                2'b01: begin
                    mm_nout    <= mm_nout - 2'd1;
                    reduce_reg <= reduce_q1;
                end
                2'b11: begin
                    if (mm_nout >= 2'd2) begin
                        reduce_reg <= reduce_q1;
                        reduce_q1  <= reduce_i;
                    end
                    else begin
                        reduce_reg <= reduce_i;
                    end
                end
                // Hold without an empty statement, avoiding lint W193.
                default: begin end
            endcase
        end
    end

    assign product_o = {p_internal, low_reg};
        
    always_ff @(posedge clk) begin
        if (!reset_n)
            push_reg <= 'b0;
        else if (zeroize)
            push_reg <= 'b0;
        else if (start_i)
            // Shift while injecting to preserve older tokens. The input geometry
            // sets token depth and therefore the sweep's retirement time.
            push_reg <= (push_reg >> 1) | push_tok;
        else
            push_reg <= push_reg >> 1;
    end

    assign push_reg_zero = push_reg == '0;

    always_ff @(posedge clk) begin
        if (zeroize) begin
            push_reg_zero_ff <= 1'b1;
            ready_tok_ff     <= 1'b0;
        end
        else begin
            push_reg_zero_ff <= push_reg_zero;
            ready_tok_ff     <= push_reg[0];
        end
    end
    
    // Registered token exit reports every retirement, unlike empty-edge detection.
    // Both methods coincide for a single in-flight multiply.
    assign ready_o = MM_PIPELINE ? ready_tok_ff : (push_reg_zero & ~push_reg_zero_ff);

    // ---------------------------------------------------------------------
    // Simulation checks for mode contracts; violations have no hardware error path.
    // ---------------------------------------------------------------------
    //synopsys translate_off
    always_ff @(posedge clk) begin
        if (reset_n && !zeroize) begin
            // Dual mode has no lane-1 non-reducing product capture.
            if (start_i && dual_i && nonreducing_i)
                $error("tessera_rsa_montgomerymultiplier: dual_i and nonreducing_i are mutually exclusive");
            // Geometry changes would retime the older drain. Check at launch;
            // upstream mode inputs may change when they are not being sampled.
            if (start_i && |push_reg && (half_i !== half_reg))
                $error("tessera_rsa_montgomerymultiplier: chained start_i with half_i %b against a chain held at %b", half_i, half_reg);
            if (start_i && |push_reg && DUAL_EN && (dual_i !== dual_reg))
                $error("tessera_rsa_montgomerymultiplier: chained start_i with dual_i %b against a chain held at %b", dual_i, dual_reg);
            // The explicit geometry override has the same chaining contract.
            if (start_i && |push_reg && (geom_i !== geom_reg))
                $error("tessera_rsa_montgomerymultiplier: chained start_i with geom_i %0d against a chain held at %0d", geom_i, geom_reg);
        end
    end
    //synopsys translate_on

endmodule