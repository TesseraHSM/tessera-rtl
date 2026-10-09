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
// tessera_rsa_modexp.sv
// -------------
// Modular exponentiation core for the RSA accelerator.
//
// Computes base_in^exponent_in mod n_in with a left-to-right Montgomery
// fixed-window ladder.  After seeding from the top window, each secret window
// uses W squarings and one table multiply.  tbl[0] is Montgomery one, so secret
// window values select data, never the schedule.  The caller supplies a fixed
// exponent_msb_index_in for secret operations; public-only shortcuts are below.
//
// mul_mode_in computes an unreduced base_in*mul_b_in on product_out without
// using or disturbing the modulus context.  It takes priority over mm_mode_in,
// an internal service computing base_in*mul_b_in*R^-1 mod n on result_out.
// Dual service mode runs two half-width contexts in one pass.
//
// mm_sq_rep_in adds dependent squarings to a service request.  Forwarding costs
// one 3*S_NUM latency plus MM_II per repeat, rather than a full latency per link.
// Repeats require mm_mode_in and square the previous result, ignoring mul_b_in.
//
// Hold inputs stable while partial results are computed; they are not all
// captured internally.
//
// Signal description:
//      n_prime_lsw_in      :   -n^(-1) mod 2^WORD_BIT_WIDTH
//      r_pow_1_mod_n_in    :   R mod n
//      r_pow_2_mod_n_in    :   R^2 mod n
//
//======================================================================

import tessera_rsa_params_pkg::*;

module tessera_rsa_modexp #(
    parameter   MODULUS_BIT_WIDTH   = RSA_KEY_SIZE,
    parameter   EXPONENT_BIT_WIDTH  = RSA_KEY_SIZE,
    parameter   WORD_BIT_WIDTH      = RSA_RADIX,
    // Public window width; reciprocal division supports non-powers of two.
    parameter   WINDOW_BITS         = RSA_WINDOW_BITS,
    // Build the dual-lane CRT datapath; tessera_rsa_ctrl selects RSA_CRT_ENABLE.
    parameter bit DUAL_EN           = 1'b0,
    // Widen dual-lane windows when DUAL_EN is set.
    parameter bit DUAL_WIN_HI       = RSA_DUAL_WIN_HI,
    // Widen full-width secret windows, sharing storage with widened dual mode.
    parameter bit SEC_WIN_HI        = RSA_SEC_WIN_HI,
    // Extra full/dual secret window bits; each bit doubles the required entries.
    parameter int unsigned WIN_EXTRA_BITS = RSA_WIN_EXTRA_BITS,
    localparam  S_NUM               = ((MODULUS_BIT_WIDTH + WORD_BIT_WIDTH - 1) / WORD_BIT_WIDTH) + 1,
    localparam  FULL_REG_SIZE       = S_NUM * WORD_BIT_WIDTH
) (
    input                                           clk,
    input                                           rst_n,

    input   wire                                    start_in,
    // Synchronously erase message-derived table and ladder state, return to
    // IDLE and propagate the erase into the multiplier.
    input   wire                                    zeroize,
    // Sampled with start_in; read product_out, not result_out, in plain MUL mode.
    input   wire                                    mul_mode_in,
    // Sampled with start_in; internal MM service uses the live modulus context
    // and returns on result_out.
    input   wire                                    mm_mode_in,
    // Half-width MM service geometry; its R must match the borrowed context.
    input   wire                                    mm_half_in,
    // Geometry code (top-stage index) for the multiply service, alongside
    // mm_half_in.  Zero means "legacy" -- decode from mm_half_in.
    input   wire [7:0]                              mm_geom_in,
    // Additional service squarings, sampled with start_in; zero means one MM.
    // Both operands forward on accept: k squarings cost (k-1)*MM_II + 3*S_NUM.
    input   wire [5:0]                              mm_sq_rep_in,
    // Hold half mode throughout the operation: overlapping multiplies share
    // geometry.  Entry, ladder and exit all require a half-width n, n', R, R^2
    // context.  Secret CRT branches use the fixed index HALF-1.
    input   wire                                    half_in,
    // Array top stage; zero decodes from half_in.  Table packing is separate:
    // a 3072-bit operand on a 4096-bit part cannot use two entries per slot.
    input   wire [7:0]                              geom_in,
    input   wire    [MODULUS_BIT_WIDTH-1:0]         mul_b_in,
    input   wire    [MODULUS_BIT_WIDTH-1:0]         base_in,
    input   wire    [EXPONENT_BIT_WIDTH-1:0]        exponent_in,
    // Top exponent bit: the ladder covers floor(index/W)+1 windows.
    // Public operations may use e's true MSB.  Secret operations must use a
    // fixed configured sweep bound, never an index derived from d.
    input   wire    [$clog2(EXPONENT_BIT_WIDTH)-1:0] exponent_msb_index_in,
    // Public-only shortcuts may trim precomputation, skip zero windows and
    // fuse the final multiply with Montgomery exit.  Timing then depends on
    // exponent values: this MUST be zero for every secret exponent.
    input   wire                                    exp_public_in,
    input   wire    [MODULUS_BIT_WIDTH-1:0]         n_in,
    input   wire    [WORD_BIT_WIDTH-1:0]            n_prime_lsw_in,
    input   wire    [MODULUS_BIT_WIDTH-1:0]         r_pow_1_mod_n_in,
    input   wire    [MODULUS_BIT_WIDTH-1:0]         r_pow_2_mod_n_in,

    // ----------------------------------------------------------------------
    // Hold dual mode throughout the operation.  Each lane is half width with
    // its own n, n', R and R^2; only the low half of each context is used.
    // Both lanes share the fixed HALF-1 exponent bound and schedule.
    // Public shortcuts are disabled: dp/dq are secret and may differ.
    // ----------------------------------------------------------------------
    input   wire                                    dual_in,
    input   wire    [MODULUS_BIT_WIDTH-1:0]         base1_in,
    input   wire    [EXPONENT_BIT_WIDTH-1:0]        exponent1_in,
    input   wire    [MODULUS_BIT_WIDTH-1:0]         n1_in,
    input   wire    [WORD_BIT_WIDTH-1:0]            n_prime1_lsw_in,
    input   wire    [MODULUS_BIT_WIDTH-1:0]         r_pow_1_mod_n1_in,
    input   wire    [MODULUS_BIT_WIDTH-1:0]         r_pow_2_mod_n1_in,
    // Lane 1 MM service operand; dual mode retires both contexts together.
    // It implies half width regardless of mm_half_in.
    input   wire    [MODULUS_BIT_WIDTH-1:0]         mul_b1_in,

    output  logic   [MODULUS_BIT_WIDTH-1:0]         result_out,
    // Lane 1 result.  Constant zero unless DUAL_EN.
    output  logic   [MODULUS_BIT_WIDTH-1:0]         result1_out,
    output  logic   [2*FULL_REG_SIZE-1:0]           product_out,
    output  logic                                   done_out
);
//-----------------------------------------------------------------------------
// Local Parameters
//-----------------------------------------------------------------------------
localparam SUBTRACTION_WORD_WIDTH   = WORD_BIT_WIDTH;

// Reciprocal division maps bit indices to windows:
// floor(x/WINDOW_BITS) == (x*WIN_RECIP)>>16 over the supported index range.
// Elaboration guards check exactness, including non-power-of-two windows.
localparam int unsigned TBL_SIZE    = 2 ** WINDOW_BITS;
localparam int unsigned WIN_RECIP   = (65536 + WINDOW_BITS - 1) / WINDOW_BITS;
localparam int unsigned NUM_WIN     = (EXPONENT_BIT_WIDTH + WINDOW_BITS - 1) / WINDOW_BITS;
localparam int unsigned WIN_IDX_W   = (NUM_WIN > 1) ? $clog2(NUM_WIN) : 1;

// ---------------------------------------------------------------------------
// Widened full/dual secret geometry; half packing has a separate width below.
// ---------------------------------------------------------------------------
localparam int unsigned WB_HI        = WINDOW_BITS + WIN_EXTRA_BITS;
localparam int unsigned TBL_SIZE_HI  = 2 ** WB_HI;
localparam int unsigned WIN_RECIP_HI = (65536 + WB_HI - 1) / WB_HI;
localparam int unsigned HALF_W       = MODULUS_BIT_WIDTH / 2;

// ---------------------------------------------------------------------------
// Dual packing uses both halves per slot, so wider windows need more slots.
// ---------------------------------------------------------------------------
localparam bit          DUAL_HI_EN   = DUAL_EN & DUAL_WIN_HI;

// ---------------------------------------------------------------------------
// Full-width secret widening reuses the slots required by widened dual mode.
// ---------------------------------------------------------------------------
localparam bit          FULL_HI_EN   = SEC_WIN_HI;
// Full/dual packing sets depth; half packing reuses these slots.
localparam int unsigned TBL_ADDR_W   = (DUAL_HI_EN | FULL_HI_EN) ? WB_HI
                                                                 : WINDOW_BITS;
localparam int unsigned TBL_DEPTH    = 2 ** TBL_ADDR_W;

// ---------------------------------------------------------------------------
// Two half-width entries per slot allow WB_HALF = TBL_ADDR_W+1 at no extra
// storage cost: 2**(WB_HALF-1) == TBL_DEPTH.
// ---------------------------------------------------------------------------
localparam int unsigned WB_HALF       = TBL_ADDR_W + 1;
localparam int unsigned TBL_SIZE_HALF = 2 ** WB_HALF;
localparam int unsigned WIN_RECIP_HALF = (65536 + WB_HALF - 1) / WB_HALF;

// Size shared indices for the widest geometry.
localparam int unsigned TBL_IDX_W   = WB_HALF;
localparam int unsigned SQ_CNT_W    = (WB_HALF > 1) ? $clog2(WB_HALF) : 1;
// Pad for every representable index at the widest stride and slice width,
// preventing out-of-bounds variable part-selects.
localparam int unsigned EXP_VEC_W   = ((2 ** WIN_IDX_W) * WB_HALF) + WB_HALF;

enum logic [2:0] {
    IDLE_STATE              = 'h0,
    BASE_TO_MONT_STATE      = 'h1,
    PRECOMP_STATE           = 'h2,
    RES_SQUARING_STATE      = 'h3,
    RES_MULT_BASE_STATE     = 'h4,
    RES_FROM_MONT_STATE     = 'h5,
    MUL_STATE               = 'h6
} opState, opState_next;


//-----------------------------------------------------------------------------
// Types and structures
//-----------------------------------------------------------------------------
typedef logic   [MODULUS_BIT_WIDTH-1:0]             modulus_t;
typedef logic   [EXPONENT_BIT_WIDTH-1:0]            exp_t;
typedef logic   [WORD_BIT_WIDTH-1:0]                word_t;
typedef logic   [$clog2(EXPONENT_BIT_WIDTH)-1:0]    exponent_bit_ind_t;
typedef logic   [WIN_IDX_W-1:0]                     win_ind_t;
typedef logic   [TBL_IDX_W-1:0]                     tbl_ind_t;
typedef logic   [SQ_CNT_W-1:0]                      sq_cnt_t;
typedef logic   [WB_HALF-1:0]                       win_val_t;



//-----------------------------------------------------------------------------
// Internal Signals
//-----------------------------------------------------------------------------
logic               mm_start;
modulus_t           mm_a;
modulus_t           mm_b;
modulus_t           mm_n;
word_t              mm_n_prime_lsw;     // LSW - least significant word
modulus_t           mm_product;
// Lane 1 of the dual-lane CRT datapath.  Constant zero unless DUAL_EN.
modulus_t           mm_a1;
modulus_t           mm_b1;
modulus_t           mm_n1;
word_t              mm_n_prime1_lsw;
modulus_t           mm_product1;
logic               mm_done;
// Launch handshake; without pipelining, accept equals done and forwarding
// requests are ignored.
logic               mm_accept;
logic               mm_fwd_a;
logic               mm_fwd_b;
// Count in-flight multiplies so completion cannot consume an older retirement.
logic [1:0]         mm_outstanding;
logic               mm_last_done;
// Remaining service squarings; zero for the final link and for ladder operations.
logic [5:0]         mm_rep_cnt;
logic [5:0]         mm_rep_cnt_next;

// Forwarding is the default; RSA_MM_NO_PIPELINE selects the serialized
// launch-after-ready reference.
`ifdef RSA_MM_NO_PIPELINE
localparam bit MM_PIPELINE = 1'b0;
`else
localparam bit MM_PIPELINE = 1'b1;
`endif
logic               mm_nonreducing;
logic               mm_reduce;
modulus_t           partial_result;
modulus_t           partial_result_next;
modulus_t           partial_result1;
modulus_t           partial_result1_next;

// Precomputed window table: tbl[w] = base^w in Montgomery form, with
// tbl[0] = R mod n so that a zero window is a multiply by one.
modulus_t                   tbl      [0:TBL_DEPTH-1];
modulus_t                   tbl_next [0:TBL_DEPTH-1];
// Centralize packing so a table write cannot clobber the other lane's half.
logic                       tbl_we;
tbl_ind_t                   tbl_wa;
modulus_t                   tbl_wd;
logic                       tbl_we1;
modulus_t                   tbl_wd1;
logic   [EXP_VEC_W-1:0]     exp_padded;
logic   [EXP_VEC_W-1:0]     exp1_padded;
win_val_t                   win_val;        // current window's exponent bits
win_val_t                   win_val1;       // lane 1's window, same index
win_ind_t                   win_index;      // windows remaining below this one
win_ind_t                   win_index_next;
tbl_ind_t                   tbl_index;      // table entry the next LAUNCH produces
tbl_ind_t                   tbl_index_next;
// Separate retirement and launch indices: accept occurs at MM_II, done at
// 3*S_NUM.  With two MMs in flight, the write index trails by at most one.
tbl_ind_t                   tbl_wr_index;
tbl_ind_t                   tbl_wr_index_next;
sq_cnt_t                    sq_cnt;         // squarings still to do in window
sq_cnt_t                    sq_cnt_next;

// Scan public windows during BASE_TO_MONT to build only tbl[2..max_win].
// Unless the scan finishes before retirement, build the full table.
win_val_t                   max_win;
win_val_t                   max_win_next;
win_ind_t                   scan_idx;
win_ind_t                   scan_idx_next;
logic                       scan_done;
logic                       scan_done_next;
logic                       scan_en;
win_val_t                   scan_win_val;
// Precompute limit is at least 2 because BASE_TO_MONT always launches tbl[2].
tbl_ind_t                   tbl_limit;
// Seed from the top window, bypassing the last entry retiring on mm_product.
modulus_t                   tbl_seed;
modulus_t                   tbl_seed1;

// Runtime geometry must remain stable for the whole ladder.
logic                       wb_hi;
// The wider window is in force -- either packing that can reach WB_HI.
logic                       dual_hi;
logic                       full_hi;
logic                       win_hi;
// The half packing running its own wider window: shortened AND secret.
logic                       half_hi;
// Dual-lane CRT.  A literal zero unless the datapath was built.
logic                       dual;
// All shortcuts use this dual-qualified signal, never the raw port: a
// lane-0-dependent schedule would leak dp and break lane 1.
logic                       exp_public;
logic [SQ_CNT_W-1:0]        sq_cnt_top;     // squarings per window, minus one
win_val_t                   win_mask;       // low win_bits ones
// Keep these 32 bits: self-determined index products would otherwise truncate
// (exponent_msb_index_in * win_recip can reach ~90M).
logic [31:0]                win_stride;     // exponent bits per window
logic [31:0]                win_recip;

assign dual       = DUAL_EN & dual_in;
assign exp_public = exp_public_in & ~dual;
assign wb_hi      = half_in & ~dual;
assign dual_hi    = dual & DUAL_WIN_HI;
// Window width depends on the public command class, not secret exponent bits.
assign full_hi    = ~wb_hi & ~dual & ~exp_public & FULL_HI_EN;
// Operand width selects packing; command class selects window width.
// Shortened public operations retain the smaller public window to avoid
// excessive precomputation.
assign half_hi    = wb_hi & ~exp_public;
assign win_hi     = dual_hi | full_hi;
assign sq_cnt_top = half_hi ? sq_cnt_t'(WB_HALF - 1)
                  : win_hi  ? sq_cnt_t'(WB_HI - 1)
                            : sq_cnt_t'(WINDOW_BITS - 1);
assign win_mask   = half_hi ? win_val_t'({WB_HALF{1'b1}})
                  : win_hi  ? win_val_t'({WB_HI{1'b1}})
                            : win_val_t'({WINDOW_BITS{1'b1}});
assign win_stride = half_hi ? 32'(WB_HALF) : win_hi ? 32'(WB_HI) : 32'(WINDOW_BITS);
assign win_recip  = half_hi ? 32'(WIN_RECIP_HALF)
                  : win_hi  ? 32'(WIN_RECIP_HI) : 32'(WIN_RECIP);

// One flop array supports three packings:
//   full: one full-width entry per slot;
//   wb_hi: entry j in slot j>>1, half j[0];
//   dual: slot j holds entry j for both lanes, lane 0 low and lane 1 high.
// Half results are zero-extended.  Reads are muxes over flops, not variable-
// latency memory accesses; secret window values do not affect cycle count.
function automatic modulus_t tbl_rd_ln(input tbl_ind_t j, input logic lane);
    logic [TBL_ADDR_W-1:0]  slot;
    logic                   half_sel;
    logic [HALF_W-1:0]      h;
    begin
        if (wb_hi) begin
            slot     = TBL_ADDR_W'(j[TBL_IDX_W-1:1]);
            half_sel = j[0];
        end
        else begin
            // Full/dual modes use the whole entry index; only dual selects a half.
            slot     = TBL_ADDR_W'(j);
            half_sel = lane;
        end
        h = half_sel ? tbl[slot][HALF_W +: HALF_W] : tbl[slot][0 +: HALF_W];
        if (wb_hi | dual) tbl_rd_ln = modulus_t'(h);
        else              tbl_rd_ln = tbl[slot];
    end
endfunction

function automatic modulus_t tbl_rd(input tbl_ind_t j);
    tbl_rd = tbl_rd_ln(j, 1'b0);
endfunction

//-----------------------------------------------------------------------------
// Logic
//-----------------------------------------------------------------------------

// Exponentiation FSM
// tbl[0] = R mod n                      (Montgomery one)
// 1. tbl[1] = MM(base, R^2 mod n)       (base in Montgomery form)
// 2. for j in [2 .. tbl_limit]:         tbl[j] = MM(tbl[j-1], tbl[1])
//    tbl_limit is 2**WINDOW_BITS-1 in general, but for a public exponent it is
//    trimmed to the largest window value that exponent actually selects.
// 3. res = tbl[w_top]                   (seed; a table read, not a multiply)
//    for each REMAINING window w, most significant first:
//        repeat WINDOW_BITS: res = MM(res, res)
//        res = MM(res, tbl[w])          (unconditional; w == 0 multiplies by 1)
// 4. res = MM(res, 1)
// 5. output res
assign exp_padded  = EXP_VEC_W'(exponent_in);
assign exp1_padded = EXP_VEC_W'(exponent1_in);

// Disable the value-dependent scan for secret exponents.
assign scan_en      = exp_public & ~scan_done & (opState == BASE_TO_MONT_STATE);
assign scan_win_val = win_val_t'(exp_padded[scan_idx * win_stride +: WB_HALF]) & win_mask;

// Use the full table unless the public scan completed.
assign tbl_limit = (exp_public & scan_done)
                 ? ((max_win < win_val_t'(2)) ? tbl_ind_t'(2) : tbl_ind_t'(max_win))
                 : (half_hi ? tbl_ind_t'(TBL_SIZE_HALF - 1)
                            : (win_hi ? tbl_ind_t'(TBL_SIZE_HI - 1)
                                      : tbl_ind_t'(TBL_SIZE - 1)));

assign tbl_seed  = (win_val == win_val_t'(tbl_index)) ? mm_product
                                                     : tbl_rd_ln(tbl_ind_t'(win_val), 1'b0);
assign tbl_seed1 = (win_val1 == win_val_t'(tbl_index)) ? mm_product1
                                                      : tbl_rd_ln(tbl_ind_t'(win_val1), 1'b1);

// Terminating states wait for the last in-flight retirement.
assign mm_last_done = mm_done & (mm_outstanding == 2'd1);

always_ff @(posedge clk) begin
    if (~rst_n | zeroize)
        mm_outstanding <= 2'd0;
    else
        case ({mm_start, mm_done})
            2'b10:   mm_outstanding <= mm_outstanding + 2'd1;
            2'b01:   mm_outstanding <= mm_outstanding - 2'd1;
            default: mm_outstanding <= mm_outstanding;
        endcase
end

always_comb begin
    opState_next = opState;
    mm_n = n_in;
    mm_n_prime_lsw = n_prime_lsw_in;
    mm_start = 1'b0;
    mm_fwd_a = 1'b0;
    mm_fwd_b = 1'b0;
    mm_rep_cnt_next = mm_rep_cnt;
    partial_result_next = partial_result;
    partial_result1_next = partial_result1;
    win_index_next = win_index;
    tbl_index_next = tbl_index;
    tbl_wr_index_next = tbl_wr_index;
    sq_cnt_next = sq_cnt;
    max_win_next = max_win;
    scan_idx_next = scan_idx;
    scan_done_next = scan_done;
    tbl_we  = 1'b0;
    tbl_we1 = 1'b0;
    tbl_wa  = '0;
    tbl_wd  = '0;
    tbl_wd1 = '0;
    done_out = 1'b0;
    result_out = mm_product;
    result1_out = mm_product1;
    mm_a = partial_result;
    mm_b = partial_result;
    mm_n1 = n1_in;
    mm_n_prime1_lsw = n_prime1_lsw_in;
    mm_a1 = partial_result1;
    mm_b1 = partial_result1;
    mm_nonreducing = 1'b0;
    // Reduce by default; the ladder explicitly opts out on intermediates.
    mm_reduce = 1'b1;

    case (opState)
        IDLE_STATE: begin
            // Only MM service requests may reload the repeat count.
            mm_rep_cnt_next = 6'd0;
            if (start_in & mul_mode_in) begin
                opState_next = MUL_STATE;
                mm_start = 1'b1;
                mm_a = base_in;
                mm_b = mul_b_in;
                mm_nonreducing = 1'b1;
            end
            else if (start_in & mm_mode_in) begin
                // Reducing service; dual lanes share the fixed MM schedule.
                opState_next = MUL_STATE;
                mm_start = 1'b1;
                mm_a = base_in;
                mm_b = mul_b_in;
                mm_a1 = base1_in;
                mm_b1 = mul_b1_in;
                mm_rep_cnt_next = mm_sq_rep_in;
            end
            else if (start_in) begin
                opState_next = BASE_TO_MONT_STATE;
                mm_start = 1'b1;
                mm_reduce = 1'b0;
                mm_a = base_in;
                mm_b = r_pow_2_mod_n_in;
                mm_a1 = base1_in;
                mm_b1 = r_pow_2_mod_n1_in;
                partial_result_next = r_pow_1_mod_n_in;
                partial_result1_next = r_pow_1_mod_n1_in;
                // Montgomery one, the table entry a zero window selects.
                tbl_we  = 1'b1;
                tbl_wa  = tbl_ind_t'(0);
                tbl_wd  = r_pow_1_mod_n_in;
                tbl_we1 = dual;
                tbl_wd1 = r_pow_1_mod_n1_in;
                // Map the top exponent bit to its window by reciprocal division.
                win_index_next = win_ind_t'(
                    ((exponent_msb_index_in * win_recip) >> 16));
                tbl_index_next = tbl_ind_t'(2);
                tbl_wr_index_next = tbl_ind_t'(2);
                sq_cnt_next    = sq_cnt_top;
                // Scan the whole exponent, top window down to window 0.
                scan_idx_next   = win_ind_t'(
                    ((exponent_msb_index_in * win_recip) >> 16));
                max_win_next    = '0;
                scan_done_next  = 1'b0;
            end
        end

        MUL_STATE: begin
            // Forward both operands on accept for chained squarings.
            // Explicit products support the serialized accept==done path.
            if ((mm_rep_cnt != 6'd0) && mm_accept) begin
                mm_start = 1'b1;
                mm_fwd_a = 1'b1;
                mm_fwd_b = 1'b1;
                mm_a  = mm_product;
                mm_b  = mm_product;
                mm_a1 = mm_product1;
                mm_b1 = mm_product1;
                mm_rep_cnt_next = mm_rep_cnt - 6'd1;
            end
            // Complete only after the final launch and final retirement.
            if (mm_last_done && (mm_rep_cnt == 6'd0)) begin
                done_out = 1'b1;
                opState_next = IDLE_STATE;
            end
        end

        BASE_TO_MONT_STATE: begin
            // One window per cycle, hidden under the multiply already in flight.
            if (scan_en) begin
                if (scan_win_val > max_win)
                    max_win_next = scan_win_val;
                if (scan_idx == '0)
                    scan_done_next = 1'b1;
                else
                    scan_idx_next = scan_idx - 1'b1;
            end
            if (mm_done) begin
                // Store base^1 using the centralized packing.
                tbl_we  = 1'b1;
                tbl_wa  = tbl_ind_t'(1);
                tbl_wd  = mm_product;
                tbl_we1 = dual;
                tbl_wd1 = mm_product1;
                mm_start = 1'b1;
                mm_reduce = 1'b0;
                if (TBL_SIZE > 2) begin
                    // tbl[2] = MM(tbl[1], tbl[1]); tbl[1] is not registered yet.
                    opState_next = PRECOMP_STATE;
                    mm_a = mm_product;
                    mm_b = mm_product;
                    mm_a1 = mm_product1;
                    mm_b1 = mm_product1;
                end
                else begin
                    opState_next = RES_SQUARING_STATE;
                    mm_a = partial_result;
                    mm_b = partial_result;
                    mm_a1 = partial_result1;
                    mm_b1 = partial_result1;
                end
            end
        end

        PRECOMP_STATE: begin
            // Table writes require a complete result at done, not accept.
            if (mm_done) begin
                tbl_we  = 1'b1;
                tbl_wa  = tbl_wr_index;
                tbl_wd  = mm_product;
                tbl_we1 = dual;
                tbl_wd1 = mm_product1;
                tbl_wr_index_next = tbl_wr_index + 1'b1;
            end

            // Forward tbl[j] and read tbl[1] to launch tbl[j+1] at MM_II.
            if (mm_accept & (tbl_index < tbl_limit)) begin
                mm_start = 1'b1;
                mm_reduce = 1'b0;
                tbl_index_next = tbl_index + 1'b1;
                mm_a  = mm_product;      // tbl[j]
                mm_fwd_a = 1'b1;
                mm_b  = tbl_rd_ln(tbl_ind_t'(1), 1'b0); // base^1
                mm_a1 = mm_product1;
                mm_b1 = tbl_rd_ln(tbl_ind_t'(1), 1'b1);
            end
            // The seed may need the final entry; wait past earlier retirements.
            else if (mm_last_done & (tbl_index >= tbl_limit)) begin
                mm_start = 1'b1;
                mm_reduce = 1'b0;
                begin
                    // A constant-time top-window table read replaces squaring
                    // Montgomery one and multiplying it by the same entry.
                    // Bypass the final entry from mm_product if selected.
                    partial_result_next = tbl_seed;
                    partial_result1_next = tbl_seed1;
                    if (win_index == '0) begin
                        // Single-window exponent: the seed is already the
                        // answer, so go straight to the Montgomery exit.
                        opState_next = RES_FROM_MONT_STATE;
                        mm_reduce = 1'b1;
                        mm_a = tbl_seed;
                        mm_b = 1'b1;
                        mm_a1 = tbl_seed1;
                        mm_b1 = 1'b1;
                    end
                    else begin
                        opState_next = RES_SQUARING_STATE;
                        win_index_next = win_index - 1'b1;
                        sq_cnt_next = sq_cnt_top;
                        mm_a = tbl_seed;
                        mm_b = tbl_seed;
                        mm_a1 = tbl_seed1;
                        mm_b1 = tbl_seed1;
                    end
                end
            end
        end

        RES_SQUARING_STATE: begin
            // Forward retiring words on accept to overlap dependent squarings.
            // Explicit operands retain the serialized fallback.
            if (mm_accept) begin
                partial_result_next = mm_product;
                partial_result1_next = mm_product1;
                mm_start = 1'b1;
                mm_reduce = 1'b0;
                if (sq_cnt == '0) begin
                    // Secret windows always take the table multiply; only
                    // public exponents may use the shortcuts below.
                    if (exp_public & (win_val == '0)) begin
                        // Skip multiplication by Montgomery one for public
                        // zero windows only; dual mode vetoes this shortcut.
                        if (win_index == '0) begin
                            opState_next = RES_FROM_MONT_STATE;
                            mm_a = mm_product;
                            mm_fwd_a = 1'b1;
                            mm_reduce = 1'b1;
                            mm_b = 1'b1;
                        end
                        else begin
                            opState_next = RES_SQUARING_STATE;
                            win_index_next = win_index - 1'b1;
                            sq_cnt_next = sq_cnt_top;
                            mm_a = mm_product;
                            mm_b = mm_product;
                            mm_fwd_a = 1'b1;
                            mm_fwd_b = 1'b1;
                        end
                    end
                    else if (exp_public & (win_index == '0)
                                        & (win_val == win_val_t'(1))) begin
                        // Public final window == 1: fuse the table multiply
                        // and Montgomery exit using the ordinary base:
                        // MM(x*R, b) = x*b.  base_in stays live throughout.
                        opState_next = RES_FROM_MONT_STATE;
                        mm_a      = mm_product;
                        mm_fwd_a  = 1'b1;
                        mm_b      = base_in;
                        mm_reduce = 1'b1;
                    end
                    else begin
                        opState_next = RES_MULT_BASE_STATE;
                        mm_a = mm_product;
                        mm_fwd_a = 1'b1;
                        mm_b = tbl_rd_ln(tbl_ind_t'(win_val), 1'b0);
                        mm_a1 = mm_product1;
                        mm_b1 = tbl_rd_ln(tbl_ind_t'(win_val1), 1'b1);
                    end
                end
                else begin
                    sq_cnt_next = sq_cnt - 1'b1;
                    mm_a = mm_product;
                    mm_b = mm_product;
                    mm_a1 = mm_product1;
                    mm_b1 = mm_product1;
                    mm_fwd_a = 1'b1;
                    mm_fwd_b = 1'b1;
                end
            end
        end

        RES_MULT_BASE_STATE: begin
            if (mm_accept) begin
                // Unconditional: MM(res, tbl[0]) == res because tbl[0] is
                // R mod n, so a zero window needs no special case.
                partial_result_next = mm_product;
                partial_result1_next = mm_product1;
                mm_start = 1'b1;
                mm_reduce = 1'b0;
                if (win_index == '0) begin
                    opState_next = RES_FROM_MONT_STATE;
                    mm_a = mm_product;
                    mm_fwd_a = 1'b1;
                    mm_reduce = 1'b1;
                    mm_b = 1'b1;
                    mm_a1 = mm_product1;
                    mm_b1 = 1'b1;
                end
                else begin
                    opState_next = RES_SQUARING_STATE;
                    win_index_next = win_index - 1'b1;
                    sq_cnt_next = sq_cnt_top;
                    mm_a = mm_product;
                    mm_b = mm_product;
                    mm_a1 = mm_product1;
                    mm_b1 = mm_product1;
                    mm_fwd_a = 1'b1;
                    mm_fwd_b = 1'b1;
                end
            end
        end

        RES_FROM_MONT_STATE: begin
            // Ignore earlier retirements; both lanes finish on the final token.
            if (mm_last_done) begin
                partial_result_next = mm_product;
                partial_result1_next = mm_product1;
                done_out = 1'b1;
                opState_next = IDLE_STATE;
            end
        end

    endcase

    // ------------------------------------------------------------------
    // Apply table packing to the FSM's write request.
    // ------------------------------------------------------------------
    for (int j = 0; j < TBL_DEPTH; j++)
        tbl_next[j] = tbl[j];
    if (tbl_we) begin
        if (wb_hi)
            // Two logical entries per slot: entry j is slot j>>1, half j[0].
            tbl_next[TBL_ADDR_W'(tbl_wa[TBL_IDX_W-1:1])][(tbl_wa[0] ? HALF_W : 0) +: HALF_W]
                = tbl_wd[HALF_W-1:0];
        else if (dual)
            // One slot per entry, lane 0 in the low half.
            tbl_next[TBL_ADDR_W'(tbl_wa)][0 +: HALF_W] = tbl_wd[HALF_W-1:0];
        else
            tbl_next[TBL_ADDR_W'(tbl_wa)] = tbl_wd;
    end
    // Dual-qualified lane 1 writes only the high half.
    if (tbl_we1)
        tbl_next[TBL_ADDR_W'(tbl_wa)][HALF_W +: HALF_W] = tbl_wd1[HALF_W-1:0];
end

always_ff @(posedge clk) begin
    if (~rst_n | zeroize)
        mm_rep_cnt <= 6'd0;
    else
        mm_rep_cnt <= mm_rep_cnt_next;
end

always_ff @(posedge clk) begin
    if (~rst_n)
        opState <= IDLE_STATE;
    else if (zeroize)
        opState <= IDLE_STATE;
    else
        opState <= opState_next;
end

always_ff @(posedge clk) begin
    if (~rst_n | zeroize) begin
        partial_result <= '0;
        partial_result1 <= '0;
        win_index      <= '0;
        tbl_index      <= '0;
        tbl_wr_index   <= '0;
        sq_cnt         <= '0;
        win_val        <= '0;
        win_val1       <= '0;
        max_win        <= '0;
        scan_idx       <= '0;
        scan_done      <= 1'b0;
        // The table holds base^w -- message-derived secret material.
        for (int j = 0; j < TBL_DEPTH; j++)
            tbl[j] <= '0;
    end
    else begin
        partial_result <= partial_result_next;
        partial_result1 <= partial_result1_next;
        win_index      <= win_index_next;
        tbl_index      <= tbl_index_next;
        tbl_wr_index   <= tbl_wr_index_next;
        sq_cnt         <= sq_cnt_next;
        max_win        <= max_win_next;
        scan_idx       <= scan_idx_next;
        scan_done      <= scan_done_next;
        win_val        <= win_val_t'(exp_padded[win_index_next * win_stride +: WB_HALF])
                          & win_mask;
        win_val1       <= win_val_t'(exp1_padded[win_index_next * win_stride +: WB_HALF])
                          & win_mask;
        for (int j = 0; j < TBL_DEPTH; j++)
            tbl[j] <= tbl_next[j];
    end
end

// synthesis translate_off
// ---------------------------------------------------------------------------
// Simulation-only profiling: state cycles, launch/retire counts and launch
// intervals per exponentiation.  Keep disabled in measurement builds.
// ---------------------------------------------------------------------------
`ifdef RSA_MODEXP_PROFILE
int unsigned prof_cyc [0:7];
int unsigned prof_starts;
int unsigned prof_dones;
int unsigned prof_first_start;
int unsigned prof_last_start;
int unsigned prof_now;
always_ff @(posedge clk) begin
    if (~rst_n | zeroize) begin
        for (int j = 0; j < 8; j++) prof_cyc[j] <= 0;
        prof_starts      <= 0;
        prof_dones       <= 0;
        prof_first_start <= 0;
        prof_last_start  <= 0;
        prof_now         <= 0;
    end
    else begin
        prof_now <= prof_now + 1;
        if (opState != IDLE_STATE)
            prof_cyc[int'(opState)] <= prof_cyc[int'(opState)] + 1;
        if (mm_start) begin
            prof_starts <= prof_starts + 1;
            prof_last_start <= prof_now;
            if (prof_starts == 0) prof_first_start <= prof_now;
        end
        if (mm_done) prof_dones <= prof_dones + 1;
        // Report on the edge back to idle, i.e. one completed exponentiation.
        if ((opState != IDLE_STATE) && (opState_next == IDLE_STATE)) begin
            $display("RSA_PROFILE dual=%0d half=%0d pub=%0d win_hi=%0d starts=%0d dones=%0d span=%0d realised_ii=%0d.%03d",
                     dual, half_in, exp_public, win_hi,
                     prof_starts + 1, prof_dones,
                     prof_now - prof_first_start,
                     (prof_now - prof_first_start) / (prof_starts > 0 ? prof_starts : 1),
                     (((prof_now - prof_first_start) * 1000) / (prof_starts > 0 ? prof_starts : 1)) % 1000);
            for (int j = 0; j < 8; j++)
                if (prof_cyc[j] != 0)
                    $display("RSA_PROFILE   state[%0d] = %0d cycles", j, prof_cyc[j]);
        end
    end
end
`endif
// synthesis translate_on

// synthesis translate_off
initial begin
    if (WINDOW_BITS < 1)
        $fatal(1, "tessera_rsa_modexp: WINDOW_BITS (%0d) must be at least 1.", WINDOW_BITS);
    // WIN_RECIP must reproduce floor(x / WINDOW_BITS) over the whole index
    // range, otherwise the ladder would start on the wrong window.
    for (int x = 0; x < (1 << WIN_IDX_W) * WINDOW_BITS; x++)
        if (((x * WIN_RECIP) >> 16) != (x / WINDOW_BITS))
            $fatal(1, "tessera_rsa_modexp: WIN_RECIP is inexact at x=%0d for WINDOW_BITS=%0d.",
                   x, WINDOW_BITS);
    // Same requirement for the half-mode geometry.
    for (int x = 0; x < (1 << WIN_IDX_W) * WB_HI; x++)
        if (((x * WIN_RECIP_HI) >> 16) != (x / WB_HI))
            $fatal(1, "tessera_rsa_modexp: WIN_RECIP_HI is inexact at x=%0d for WB_HI=%0d.",
                   x, WB_HI);
    // WINDOW_BITS >= 2 ensures PRECOMP builds entries needed by wider windows.
    if (WINDOW_BITS < 2)
        $fatal(1, "tessera_rsa_modexp: WINDOW_BITS (%0d) must be at least 2.", WINDOW_BITS);
    // And for the half packing's own window, which is the widest of the three.
    for (int x = 0; x < (1 << WIN_IDX_W) * WB_HALF; x++)
        if (((x * WIN_RECIP_HALF) >> 16) != (x / WB_HALF))
            $fatal(1, "tessera_rsa_modexp: WIN_RECIP_HALF is inexact at x=%0d for WB_HALF=%0d.",
                   x, WB_HALF);
    // Two entries per slot require 2**(WB_HALF-1) slots, exactly TBL_DEPTH.
    if ((2 ** (WB_HALF - 1)) > TBL_DEPTH)
        $fatal(1, "tessera_rsa_modexp: half window WB_HALF=%0d needs %0d slots, table has %0d.",
               WB_HALF, 2 ** (WB_HALF - 1), TBL_DEPTH);
    // Half packing requires an even modulus width.
    if ((MODULUS_BIT_WIDTH % 2) != 0)
        $fatal(1, "tessera_rsa_modexp: MODULUS_BIT_WIDTH (%0d) must be even.",
               MODULUS_BIT_WIDTH);
end
// synthesis translate_on

tessera_rsa_montgomerymultiplier #(
    .MODULUS_WIDTH  (MODULUS_BIT_WIDTH),
    .RADIX          (WORD_BIT_WIDTH),
    .DUAL_EN        (DUAL_EN)
)
tessera_rsa_montgomerymultiplier
(
    .clk        (clk),
    .reset_n    (rst_n),

    .start_i        (mm_start),
    .zeroize        (zeroize),
    .nonreducing_i  (mm_nonreducing),
    .reduce_i       (mm_reduce),
    .opa_i          (mm_a),
    .opb_i          (mm_b),
    .n_i            (mm_n),
    .n_prime_i      (mm_n_prime_lsw),
    // Squarings forward both operands; table multiplies forward only a.
    // The serialized build ignores forwarding and uses explicit operands.
    .fwd_a_i        (mm_fwd_a),
    .fwd_b_i        (mm_fwd_b),
    // Select service or ladder geometry; it must match the active context.
    .half_i         (mm_mode_in ? mm_half_in : half_in),
    .geom_i         (mm_mode_in ? mm_geom_in : geom_in),
    // Dual implies half width for ladders and reducing services, never plain MUL.
    .dual_i         (dual & ~mul_mode_in),
    .opa1_i         (mm_a1[MODULUS_BIT_WIDTH/2-1:0]),
    .opb1_i         (mm_b1[MODULUS_BIT_WIDTH/2-1:0]),
    .n1_i           (mm_n1[MODULUS_BIT_WIDTH/2-1:0]),
    .n_prime1_i     (mm_n_prime1_lsw),
    .p_o            (mm_product),
    .p1_o           (mm_product1),
    .product_o      (product_out),
    .ready_o        (mm_done),
    .accept_o       (mm_accept)
);
    
endmodule