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
// rsa_modexp_tb.sv
// ----------------
// Check modular exponentiation results and constant latency within each pass.
//
// Sample a free-running cycle counter at start_in and done_out; report the
// delta in the Caliptra convention:
//
//     *** modexp test processing time = N cycles.
//
// Require result_out == base^exponent mod n and equal cycle counts across
// exponents with different Hamming weights to detect skipped dummy multiplies.
//
// Vector sources:
//   * tb/rsa_modexp_vector_gen.py: random vectors checked against Python pow().
//   * tb/rsa_acvp_kat_gen.py: NIST ACVP RSASP1 known answers, independent of
//     the local model, with 13 distinct keys per size available.
//     See tb/test_vectors/acvp/PROVENANCE.md.
//
//======================================================================

// Mirror rtl/tessera_rsa_params_pkg.sv defines; the separate TB library cannot import
// it.  Override with e.g. +define+RSA_KEY_SIZE_CONFIG=3072.
`ifndef RSA_WINDOW_BITS_PUB_CONFIG
  `define RSA_WINDOW_BITS_PUB_CONFIG 3
`endif
`ifndef RSA_KEY_SIZE_CONFIG
  `define RSA_KEY_SIZE_CONFIG 4096
`endif
`ifndef RSA_RADIX_CONFIG
  `define RSA_RADIX_CONFIG 64
`endif

module rsa_modexp_tb #(
    parameter   OPERAND_WIDTH   = `RSA_KEY_SIZE_CONFIG,
    parameter   WORD_WIDTH      = `RSA_RADIX_CONFIG,
    parameter   TEST_VECTOR_NUM = 2,
    // Of 15 ACVP cases per size, the generator excludes only 2 with message >= n.
    parameter   KAT_VECTOR_NUM  = 13,
    // Limit costly secret KATs to three keys by default; timing needs >= 2.
    // +KAT_SEC_ALL runs all 13.  Public KATs always run in full.
    parameter   KAT_SEC_DEFAULT = 3,
    // Enable dual-lane coverage by default; 0 selects the non-CRT build.
    parameter bit DUAL_EN_TB    = 1'b1
  )
  ();

  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  parameter CLK_HALF_PERIOD = 1;
  parameter CLK_PERIOD      = 2 * CLK_HALF_PERIOD;

  localparam                  STAT_CNT_WIDTH = 64;
  localparam  int unsigned    S_NUM   = ((OPERAND_WIDTH + WORD_WIDTH - 1) / WORD_WIDTH) + 1;
  localparam  int unsigned    MM_CYCLES = 3 * S_NUM;

  // Fixed-window ladder, WINDOW_BITS exponent bits per window:
  //   1 MM to enter Montgomery domain
  //   2**W - 2 MM to build table entries 2 .. 2**W-1
  //   (W + 1) MM per window (W squarings + one table multiply)
  //   1 MM to leave Montgomery domain
  // W = 1 reduces to 2 + 2*OPERAND_WIDTH, the square-and-multiply-always cost.
  localparam  int unsigned    WIN_BITS  = `RSA_WINDOW_BITS_PUB_CONFIG;
  localparam  int unsigned    TBL_SIZE  = 2 ** WIN_BITS;
  localparam  int unsigned    NUM_WIN   = (OPERAND_WIDTH + WIN_BITS - 1) / WIN_BITS;
  localparam  int unsigned    EXPECTED_MM_OPS = 1 + (TBL_SIZE - 2)
                                              + NUM_WIN * (WIN_BITS + 1) + 1;

  //----------------------------------------------------------------
  // Type definitions
  //----------------------------------------------------------------
  typedef bit     [STAT_CNT_WIDTH-1:0]            stat_t;
  typedef bit     [OPERAND_WIDTH-1:0]             operand_t;
  typedef bit     [WORD_WIDTH-1:0]                word_t;

  typedef struct packed {
      operand_t   base;
      operand_t   exponent;
      operand_t   n;
      operand_t   n_prime_lsw;    // only the low WORD_WIDTH bits are used
      operand_t   r_pow_1_mod_n;
      operand_t   r_pow_2_mod_n;
      operand_t   result;
  } test_vector_t;

  //----------------------------------------------------------------
  // Register and Wire declarations.
  //----------------------------------------------------------------
  stat_t      cycle_ctr;
  stat_t      error_ctr;
  stat_t      tc_ctr;
  stat_t      skip_ctr;
  stat_t      start_time;
  stat_t      end_time;
  stat_t      min_time;
  stat_t      max_time;

  logic       clk_tb;
  logic       reset_n_tb;

  logic       start_tb;
  logic       zeroize_tb;
  operand_t   base_tb;
  operand_t   exponent_tb;
  logic [$clog2(OPERAND_WIDTH)-1:0] exp_msb_index_tb;
  logic                             exp_public_tb;
  // Hold half select for the whole exponentiation: half_reg is shared.
  logic                             half_tb;
  operand_t   n_tb;
  word_t      n_prime_lsw_tb;
  operand_t   r_pow_1_tb;
  operand_t   r_pow_2_tb;
  operand_t   result_tb;
  // Lane 1 of the dual-lane CRT datapath.  Driven only by modexp_dual_pass().
  logic                             dual_tb;
  // tessera_rsa_mont_const's reducing-multiply service; active only in the MM pass.
  logic                             mm_mode_tb;
  logic                             mm_half_tb;
  operand_t   mul_b_tb;
  operand_t   mul_b1_tb;
  operand_t   base1_tb;
  operand_t   exponent1_tb;
  operand_t   n1_tb;
  word_t      n_prime1_lsw_tb;
  operand_t   r_pow_1_1_tb;
  operand_t   r_pow_2_1_tb;
  operand_t   result1_tb;
  // Only meaningful in plain-multiply mode, which this TB does not drive.
  logic [2*(((OPERAND_WIDTH + WORD_WIDTH - 1)/WORD_WIDTH + 1)*WORD_WIDTH)-1:0] product_unused_tb;
  logic       done_tb;
  int         test_vector_cnt;

  // Sized for the larger of the two vector sources.
  localparam  int unsigned MAX_VECTORS =
      (KAT_VECTOR_NUM > TEST_VECTOR_NUM) ? KAT_VECTOR_NUM : TEST_VECTOR_NUM;

  test_vector_t test_vectors[MAX_VECTORS];

  //----------------------------------------------------------------
  // Device Under Test.
  //----------------------------------------------------------------
  tessera_rsa_modexp #(
      .MODULUS_BIT_WIDTH  (OPERAND_WIDTH),
      .EXPONENT_BIT_WIDTH (OPERAND_WIDTH),
      .WORD_BIT_WIDTH     (WORD_WIDTH),
      .WINDOW_BITS        (WIN_BITS),
      .DUAL_EN            (DUAL_EN_TB)
  )
  modexp_dut (
      .clk                (clk_tb),
      .rst_n              (reset_n_tb),

      .start_in           (start_tb),
      .zeroize            (zeroize_tb),
      // Plain unreduced multiply is covered in rsa_top_tb.
      .mul_mode_in        (1'b0),
      // Drive the service select even when idle; floating Z can send the FSM
      // into MUL_STATE through an unknown start_in & mm_mode_in.
      .mm_mode_in         (mm_mode_tb),
      .mul_b_in           (mul_b_tb),
      .base_in            (base_tb),
      .exponent_in        (exponent_tb),
      .exponent_msb_index_in (exp_msb_index_tb),
      .exp_public_in         (exp_public_tb),
      // Drive the service width select to avoid an unknown selected geometry.
      .mm_half_in            (mm_half_tb),
      .mm_geom_in            (8'd0),
      .mm_sq_rep_in          (6'd0),
      .half_in               (half_tb),
      .geom_in               (8'd0),
      .n_in               (n_tb),
      .n_prime_lsw_in     (n_prime_lsw_tb),
      .r_pow_1_mod_n_in   (r_pow_1_tb),
      .r_pow_2_mod_n_in   (r_pow_2_tb),

      // Drive lane 1 even with DUAL_EN_TB=0 to avoid VCS Warning-[TFIPC].
      .dual_in            (dual_tb),
      .base1_in           (base1_tb),
      .exponent1_in       (exponent1_tb),
      .n1_in              (n1_tb),
      .n_prime1_lsw_in    (n_prime1_lsw_tb),
      .r_pow_1_mod_n1_in  (r_pow_1_1_tb),
      .r_pow_2_mod_n1_in  (r_pow_2_1_tb),
      .mul_b1_in          (mul_b1_tb),

      .result_out         (result_tb),
      .result1_out        (result1_tb),
      .product_out        (product_unused_tb),
      .done_out           (done_tb)
  );

  //----------------------------------------------------------------
  // clk_gen
  //----------------------------------------------------------------
  always
    begin : clk_gen
      #CLK_HALF_PERIOD;
      clk_tb = !clk_tb;
    end

  //----------------------------------------------------------------
  // sys_monitor - free running cycle counter, the latency instrument.
  //----------------------------------------------------------------
  always
    begin : sys_monitor
      #(CLK_PERIOD);
      cycle_ctr = cycle_ctr + 1;
    end

  //----------------------------------------------------------------
  // reset_dut()
  //----------------------------------------------------------------
  task reset_dut;
    begin
      $display("*** Toggle reset.");
      reset_n_tb = 0;
      #(2 * CLK_PERIOD);
      reset_n_tb = 1;
      #(2 * CLK_PERIOD);
    end
  endtask

  //----------------------------------------------------------------
  // init_sim()
  //----------------------------------------------------------------
  task init_sim;
    begin
      cycle_ctr      = 0;
      error_ctr      = 0;
      tc_ctr         = 0;
      skip_ctr       = 0;
      min_time       = {STAT_CNT_WIDTH{1'b1}};
      max_time       = 0;

      clk_tb         = 0;
      reset_n_tb     = 0;

      start_tb       = 0;
      zeroize_tb     = 0;
      base_tb        = 0;
      exponent_tb    = 0;
      exp_msb_index_tb = OPERAND_WIDTH - 1;
      exp_public_tb    = 0;
      half_tb          = 0;
      n_tb           = 0;
      n_prime_lsw_tb = 0;
      r_pow_1_tb     = 0;
      r_pow_2_tb     = 0;
      dual_tb        = 0;
      mm_mode_tb     = 0;
      mm_half_tb     = 0;
      mul_b_tb       = 0;
      mul_b1_tb      = 0;
      base1_tb       = 0;
      exponent1_tb   = 0;
      n1_tb          = 0;
      n_prime1_lsw_tb= 0;
      r_pow_1_1_tb   = 0;
      r_pow_2_1_tb   = 0;
    end
  endtask

  //----------------------------------------------------------------
  // display_test_results()
  //
  // Report accumulated correctness and constant-time failures.
  //----------------------------------------------------------------
  task display_test_results;
    begin
      $display("");
      $display("*** Expected sec: %0d MM ops x %0d cycles = %0d cycles (plus FSM overhead).",
               EXPECTED_MM_OPS, MM_CYCLES, EXPECTED_MM_OPS * MM_CYCLES);

      if (error_ctr == 0)
        begin
          $display("*** All %02d test cases completed successfully", tc_ctr);
          if (skip_ctr != 0)
            $display("*** NOTE: %0d pass(es) were SKIPPED for missing vectors.", skip_ctr);
          $display("* TESTCASE PASSED");
        end
      else
        begin
          $display("*** %02d tests completed - %02d test cases did not complete successfully.",
                   tc_ctr, error_ctr);
          $display("* TESTCASE FAILED");
        end
    end
  endtask

  //----------------------------------------------------------------
  // wait_done()
  //----------------------------------------------------------------
  task wait_done;
    begin
      while (!done_tb)
        begin
          #(CLK_PERIOD);
        end
    end
  endtask

  //----------------------------------------------------------------
  // modexp_single_test()
  //----------------------------------------------------------------
  task modexp_single_test(input int tc_number, input test_vector_t tv,
                          input logic [$clog2(OPERAND_WIDTH)-1:0] msb_index,
                          input logic is_public,
                          input string pass_name);
    begin
      $display("*** TC %0d modexp test started.", tc_number);
      tc_ctr = tc_ctr + 1;

      base_tb        = tv.base;
      exponent_tb    = tv.exponent;
      n_tb           = tv.n;
      n_prime_lsw_tb = tv.n_prime_lsw[WORD_WIDTH-1:0];
      exp_msb_index_tb = msb_index;
      exp_public_tb    = is_public;
      r_pow_1_tb     = tv.r_pow_1_mod_n;
      r_pow_2_tb     = tv.r_pow_2_mod_n;

      start_time     = cycle_ctr;
      start_tb       = 1;
      #(CLK_PERIOD);
      start_tb       = 0;

      wait_done();
      end_time = cycle_ctr - start_time;

      $display("*** modexp_%0s test processing time = %01d cycles.", pass_name, end_time);

      if (end_time < min_time) min_time = end_time;
      if (end_time > max_time) max_time = end_time;

      if (result_tb != tv.result)
        begin
          $display("*** ERROR: TC %0d wrong result.", tc_number);
          $display("  Expected: 0x%096x", tv.result);
          $display("  Got:      0x%096x", result_tb);
          error_ctr = error_ctr + 1;
        end

      // Let the FSM return to IDLE before the next vector.
      #(2 * CLK_PERIOD);
    end
  endtask

  //----------------------------------------------------------------
  // modexp_pass()
  //----------------------------------------------------------------
  // Python pow() reference vectors; run_loaded_pass() also checks timing.
  task modexp_pass(input string kind,
                   input logic [$clog2(OPERAND_WIDTH)-1:0] msb_index,
                   input logic is_public);
      string fname;
      begin
          fname = $sformatf("rsa_modexp_%0s_vectors_%0d_key_%0d_word_%0d.hex",
                            kind, TEST_VECTOR_NUM, OPERAND_WIDTH, WORD_WIDTH);
          read_test_vectors(fname, TEST_VECTOR_NUM);
          run_loaded_pass(kind, msb_index, is_public);
      end
  endtask

  //----------------------------------------------------------------
  // modexp_half_pass()
  //----------------------------------------------------------------
  // Test one CRT branch with KEY/2-bit modulus/exponent and half-width R.
  // Python pow() goldens detect use of full-width R in the shortened ladder.
  // Hold half_in throughout; exp_public remains 0 because the exponent is
  // secret, regardless of its width.  Constant-time checks still apply.
  task modexp_half_pass();
      string fname;
      int    fh;
      begin
          fname = $sformatf("rsa_modexp_half_vectors_%0d_key_%0d_word_%0d.hex",
                            TEST_VECTOR_NUM, OPERAND_WIDTH, WORD_WIDTH);
          fh = $fopen(fname, "r");
          if (fh == 0) begin
              // Missing vectors are a coverage skip, not a pass.
              $display("*** WARNING: SKIPPING half-width ladder pass, no vector file %0s.",
                       fname);
              $display("***          Generate with: python3 rsa_modexp_vector_gen.py %0d %0d %0d --half",
                       TEST_VECTOR_NUM, OPERAND_WIDTH, WORD_WIDTH);
              skip_ctr = skip_ctr + 1;
          end
          else begin
              $fclose(fh);
              read_test_vectors(fname, TEST_VECTOR_NUM);
              half_tb = 1'b1;
              run_loaded_pass("half", (OPERAND_WIDTH / 2) - 1, 1'b0);
              half_tb = 1'b0;
          end
      end
  endtask

  //----------------------------------------------------------------
  // modexp_dual_single_test()
  //----------------------------------------------------------------
  // One start/done covers two independent half-width exponentiations.
  // Check both results to catch lane mirroring.
  task modexp_dual_single_test(input int tc_number,
                               input test_vector_t tv0,
                               input test_vector_t tv1,
                               input logic [$clog2(OPERAND_WIDTH)-1:0] msb_index,
                               input string pass_name);
    begin
      $display("*** TC %0d modexp dual test started.", tc_number);
      tc_ctr = tc_ctr + 1;

      base_tb          = tv0.base;
      exponent_tb      = tv0.exponent;
      n_tb             = tv0.n;
      n_prime_lsw_tb   = tv0.n_prime_lsw[WORD_WIDTH-1:0];
      r_pow_1_tb       = tv0.r_pow_1_mod_n;
      r_pow_2_tb       = tv0.r_pow_2_mod_n;

      base1_tb         = tv1.base;
      exponent1_tb     = tv1.exponent;
      n1_tb            = tv1.n;
      n_prime1_lsw_tb  = tv1.n_prime_lsw[WORD_WIDTH-1:0];
      r_pow_1_1_tb     = tv1.r_pow_1_mod_n;
      r_pow_2_1_tb     = tv1.r_pow_2_mod_n;

      // Match tessera_rsa_crt_ctrl: both secret lanes share the public HALF-1 schedule.
      exp_msb_index_tb = msb_index;
      exp_public_tb    = 1'b0;
      half_tb          = 1'b1;
      dual_tb          = 1'b1;

      start_time     = cycle_ctr;
      start_tb       = 1;
      #(CLK_PERIOD);
      start_tb       = 0;

      wait_done();
      end_time = cycle_ctr - start_time;

      $display("*** modexp_%0s test processing time = %01d cycles.", pass_name, end_time);

      if (end_time < min_time) min_time = end_time;
      if (end_time > max_time) max_time = end_time;

      if (result_tb != tv0.result)
        begin
          $display("*** ERROR: TC %0d wrong LANE 0 result.", tc_number);
          $display("  Expected: 0x%096x", tv0.result);
          $display("  Got:      0x%096x", result_tb);
          error_ctr = error_ctr + 1;
        end

      if (result1_tb != tv1.result)
        begin
          $display("*** ERROR: TC %0d wrong LANE 1 result.", tc_number);
          $display("  Expected: 0x%096x", tv1.result);
          $display("  Got:      0x%096x", result1_tb);
          error_ctr = error_ctr + 1;
        end

      half_tb = 1'b0;
      dual_tb = 1'b0;

      // Let the FSM return to IDLE before the next vector.
      #(2 * CLK_PERIOD);
    end
  endtask

  //----------------------------------------------------------------
  // modexp_dual_pass()
  //----------------------------------------------------------------
  // Pair half-width vectors i and (i+1) % cnt to expose cross-lane coupling.
  // At least two distinct vectors are needed to detect lane mirroring.
  // dp and dq are secret: the shared schedule must have constant latency.
  task modexp_dual_pass();
      string fname;
      int    fh;
      begin
          if (!DUAL_EN_TB) begin
              $display("*** WARNING: SKIPPING dual-lane pass, DUAL_EN_TB is 0.");
              skip_ctr = skip_ctr + 1;
          end
          else begin
              fname = $sformatf("rsa_modexp_half_vectors_%0d_key_%0d_word_%0d.hex",
                                TEST_VECTOR_NUM, OPERAND_WIDTH, WORD_WIDTH);
              fh = $fopen(fname, "r");
              if (fh == 0) begin
                  $display("*** WARNING: SKIPPING dual-lane pass, no vector file %0s.",
                           fname);
                  $display("***          Generate with: python3 rsa_modexp_vector_gen.py %0d %0d %0d --half",
                           TEST_VECTOR_NUM, OPERAND_WIDTH, WORD_WIDTH);
                  skip_ctr = skip_ctr + 1;
              end
              else begin
                  $fclose(fh);
                  read_test_vectors(fname, TEST_VECTOR_NUM);
                  if (test_vector_cnt < 2) begin
                      $display("*** WARNING: SKIPPING dual-lane pass, need >= 2 half vectors, have %0d.",
                               test_vector_cnt);
                      skip_ctr = skip_ctr + 1;
                  end
                  else begin
                      min_time = {STAT_CNT_WIDTH{1'b1}};
                      max_time = 0;

                      for (int i = 0; i < test_vector_cnt; i++) begin: dual_vector_loop
                          modexp_dual_single_test(i, test_vectors[i],
                                                  test_vectors[(i + 1) % test_vector_cnt],
                                                  (OPERAND_WIDTH / 2) - 1, "dual");
                      end

                      $display("*** modexp_dual latency: min = %0d, max = %0d cycles (%0d ladder bits).",
                               min_time, max_time, OPERAND_WIDTH / 2);

                      if (min_time != max_time) begin
                          $display("*** ERROR: modexp_dual latency is data dependent (spread = %0d cycles).",
                                   max_time - min_time);
                          $display("***        A secret-exponent operation must be constant time.");
                          error_ctr = error_ctr + 1;
                      end
                  end
              end
          end
      end
  endtask

  //----------------------------------------------------------------
  // mm_single()
  //----------------------------------------------------------------
  // Exercise tessera_rsa_mont_const's reducing-multiply service; observe lane 1 only
  // when do_dual is set.
  task mm_single(input operand_t a0, input operand_t b0, input operand_t n0,
                 input word_t np0,
                 input operand_t a1, input operand_t b1, input operand_t n1,
                 input word_t np1,
                 input logic do_dual,
                 output operand_t out0, output operand_t out1,
                 output int unsigned cycles);
    begin
      base_tb         = a0;
      mul_b_tb        = b0;
      n_tb            = n0;
      n_prime_lsw_tb  = np0;
      base1_tb        = a1;
      mul_b1_tb       = b1;
      n1_tb           = n1;
      n_prime1_lsw_tb = np1;

      // Match the reference's half-width geometry even though dual implies half.
      mm_mode_tb      = 1'b1;
      mm_half_tb      = 1'b1;
      dual_tb         = do_dual;

      start_time = cycle_ctr;
      start_tb   = 1;
      #(CLK_PERIOD);
      start_tb   = 0;

      wait_done();
      cycles = cycle_ctr - start_time;

      out0 = result_tb;
      out1 = result1_tb;

      mm_mode_tb = 1'b0;
      mm_half_tb = 1'b0;
      dual_tb    = 1'b0;
      mul_b_tb   = '0;
      mul_b1_tb  = '0;

      #(2 * CLK_PERIOD);
    end
  endtask

  //----------------------------------------------------------------
  // modexp_dual_mm_pass()
  //----------------------------------------------------------------
  // Compare dual service multiplies with two single-lane reference runs:
  // MM(base_i, R2_i) and MM(base_j, R2_j), each under its own context.
  // Both results must match to detect crossed operands or lane mirroring;
  // dual latency must equal the single-lane latency.
  task modexp_dual_mm_pass();
      string       fname;
      int          fh;
      int unsigned c_ref0, c_ref1, c_dual;
      operand_t    ref0, ref1, dual0, dual1, junk;
      int          j;
      begin
          if (!DUAL_EN_TB) begin
              $display("*** WARNING: SKIPPING dual single-shot MM pass, DUAL_EN_TB is 0.");
              skip_ctr = skip_ctr + 1;
          end
          else begin
              fname = $sformatf("rsa_modexp_half_vectors_%0d_key_%0d_word_%0d.hex",
                                TEST_VECTOR_NUM, OPERAND_WIDTH, WORD_WIDTH);
              fh = $fopen(fname, "r");
              if (fh == 0) begin
                  $display("*** WARNING: SKIPPING dual single-shot MM pass, no vector file %0s.",
                           fname);
                  skip_ctr = skip_ctr + 1;
              end
              else begin
                  $fclose(fh);
                  read_test_vectors(fname, TEST_VECTOR_NUM);
                  if (test_vector_cnt < 2) begin
                      $display("*** WARNING: SKIPPING dual single-shot MM pass, need >= 2 half vectors, have %0d.",
                               test_vector_cnt);
                      skip_ctr = skip_ctr + 1;
                  end
                  else begin
                      for (int i = 0; i < test_vector_cnt; i++) begin: dual_mm_loop
                          j = (i + 1) % test_vector_cnt;
                          $display("*** TC %0d dual single-shot MM test started.", i);
                          tc_ctr = tc_ctr + 1;

                          mm_single(test_vectors[i].base,
                                    test_vectors[i].r_pow_2_mod_n,
                                    test_vectors[i].n,
                                    test_vectors[i].n_prime_lsw[WORD_WIDTH-1:0],
                                    '0, '0, '0, '0, 1'b0,
                                    ref0, junk, c_ref0);

                          mm_single(test_vectors[j].base,
                                    test_vectors[j].r_pow_2_mod_n,
                                    test_vectors[j].n,
                                    test_vectors[j].n_prime_lsw[WORD_WIDTH-1:0],
                                    '0, '0, '0, '0, 1'b0,
                                    ref1, junk, c_ref1);

                          mm_single(test_vectors[i].base,
                                    test_vectors[i].r_pow_2_mod_n,
                                    test_vectors[i].n,
                                    test_vectors[i].n_prime_lsw[WORD_WIDTH-1:0],
                                    test_vectors[j].base,
                                    test_vectors[j].r_pow_2_mod_n,
                                    test_vectors[j].n,
                                    test_vectors[j].n_prime_lsw[WORD_WIDTH-1:0],
                                    1'b1,
                                    dual0, dual1, c_dual);

                          if (dual0 !== ref0) begin
                              $display("*** ERROR: TC %0d dual MM lane 0 disagrees with the single-lane reference.", i);
                              $display("  Expected: 0x%096x", ref0);
                              $display("  Got:      0x%096x", dual0);
                              error_ctr = error_ctr + 1;
                          end

                          if (dual1 !== ref1) begin
                              $display("*** ERROR: TC %0d dual MM lane 1 disagrees with the single-lane reference.", i);
                              $display("  Expected: 0x%096x", ref1);
                              $display("  Got:      0x%096x", dual1);
                              error_ctr = error_ctr + 1;
                          end

                          if (c_dual != c_ref0) begin
                              $display("*** ERROR: TC %0d dual MM costs %0d cycles, single-lane MM costs %0d.",
                                       i, c_dual, c_ref0);
                              $display("***        The second context is supposed to be free.");
                              error_ctr = error_ctr + 1;
                          end
                      end

                      $display("*** modexp_dual_mm: %0d cycles per reducing multiply, one lane or two.",
                               c_dual);
                  end
              end
          end
      end
  endtask

  //----------------------------------------------------------------
  // kat_pass()
  //----------------------------------------------------------------
  // NIST ACVP known answers exercise both key directions:
  //   kat_sec:  s = m^d mod n   (RSASP1, signature primitive)
  //   kat_pub:  m = s^e mod n   (RSAVP1, verification primitive, e = 65537)
  //----------------------------------------------------------------
  task kat_pass(input string kind,
                input logic [$clog2(OPERAND_WIDTH)-1:0] msb_index,
                input int max_run);
      string fname;
      begin
          fname = $sformatf("rsa_modexp_kat_%0s_vectors_%0d_key_%0d_word_%0d.hex",
                            kind, KAT_VECTOR_NUM, OPERAND_WIDTH, WORD_WIDTH);
          read_test_vectors(fname, KAT_VECTOR_NUM);
          if (max_run < test_vector_cnt) begin
              $display("*** NIST ACVP %0s: running %0d of %0d vectors (pass +KAT_SEC_ALL for all).",
                       kind, max_run, test_vector_cnt);
              test_vector_cnt = max_run;
          end else begin
              $display("*** NIST ACVP %0s: running all %0d vectors.",
                       kind, test_vector_cnt);
          end
          run_loaded_pass($sformatf("kat_%0s", kind), msb_index,
                          (kind == "pub"));
      end
  endtask

  //----------------------------------------------------------------
  // run_loaded_pass()
  //----------------------------------------------------------------
  // Require equal latency within each loaded pass.  Reset min/max per pass:
  // public and secret ladders may differ because public e need not be hidden.
  //----------------------------------------------------------------
  task run_loaded_pass(input string kind,
                       input logic [$clog2(OPERAND_WIDTH)-1:0] msb_index,
                       input logic is_public);
      begin
          min_time = {STAT_CNT_WIDTH{1'b1}};
          max_time = 0;

          for (int i = 0; i < test_vector_cnt; i++) begin: test_vector_loop
              modexp_single_test(i, test_vectors[i], msb_index, is_public, kind);
          end

          $display("*** modexp_%0s latency: min = %0d, max = %0d cycles (%0d ladder bits).",
                   kind, min_time, max_time, msb_index + 1);

          if (min_time != max_time) begin
              $display("*** ERROR: modexp_%0s latency is data dependent (spread = %0d cycles).",
                       kind, max_time - min_time);
              $display("***        A secret-exponent operation must be constant time.");
              error_ctr = error_ctr + 1;
          end
      end
  endtask

  //----------------------------------------------------------------
  // read_test_vectors()
  //
  // Seven whitespace-delimited hex fields: base, exponent, n, n_prime_lsw,
  // R mod n, R^2 mod n, result (rsa_modexp_vector_gen.py / rsa_acvp_kat_gen.py).
  // expected_cnt prevents stale or truncated files from silently reducing coverage.
  //----------------------------------------------------------------
  task read_test_vectors(input string fname, input int expected_cnt);
      integer values_per_test_vector;
      integer line_cnt;
      integer fin;
      integer rv;
      operand_t val;
      test_vector_t test_vector;

      values_per_test_vector = 7;
      line_cnt = 0;
      test_vector_cnt = 0;

      fin = $fopen(fname, "r");
      if (fin == 0) begin
          $display("*** ERROR: can't open vector file %s", fname);
          error_ctr = error_ctr + 1;
          $finish;
      end
      while (!$feof(fin)) begin
          rv = $fscanf(fin, "%h\n", val);
          if (rv != 1) begin
              $error("Failed to read a matching string");
              $fclose(fin);
              $finish;
          end
          case (line_cnt % values_per_test_vector)
              0: test_vector.base          = val;
              1: test_vector.exponent      = val;
              2: test_vector.n             = val;
              3: test_vector.n_prime_lsw   = val;
              4: test_vector.r_pow_1_mod_n = val;
              5: test_vector.r_pow_2_mod_n = val;
              6: begin
                 test_vector.result        = val;
                 if (test_vector_cnt >= MAX_VECTORS) begin
                     $display("*** ERROR: %s holds more than %0d vectors.",
                              fname, MAX_VECTORS);
                     error_ctr = error_ctr + 1;
                     $fclose(fin);
                     $finish;
                 end
                 test_vectors[test_vector_cnt] = test_vector;
                 test_vector_cnt++;
              end
          endcase

          line_cnt++;
      end
      $fclose(fin);

      if (test_vector_cnt != expected_cnt) begin
          $display("*** ERROR: %s holds %0d vectors, expected %0d.",
                   fname, test_vector_cnt, expected_cnt);
          error_ctr = error_ctr + 1;
      end

      $display("Read %0d test vectors from %s", test_vector_cnt, fname);
  endtask

  //----------------------------------------------------------------
  // main
  //----------------------------------------------------------------
  initial
    begin : main
      string fname;

      $display("   -= Testbench for tessera_rsa_modexp started =-");
      $display("    =====================================\n");
      $display("*** CONFIG: KEY_SIZE = %0d, RADIX = %0d, S_NUM = %0d, MM = %0d cycles, WINDOW = %0d bits.",
               OPERAND_WIDTH, WORD_WIDTH, S_NUM, MM_CYCLES, WIN_BITS);

      init_sim();
      reset_dut();

      // Public-key op: e = 65537, so the ladder only needs bits [16:0].
      modexp_pass("pub", 16, 1'b1);
      // Private-key op: full width, fixed, independent of the value of d.
      modexp_pass("sec", OPERAND_WIDTH - 1, 1'b0);

      // Measure a single half-width CRT branch.
      modexp_half_pass();

      // Run both CRT branches using the same half-width vectors.
      modexp_dual_pass();

      // The dual single-shot reducing multiply, the tessera_rsa_mont_const service path.
      modexp_dual_mm_pass();

      // Known-answer checks independent of the local Python model.
      kat_pass("pub", 16, KAT_VECTOR_NUM);
      kat_pass("sec", OPERAND_WIDTH - 1,
               $test$plusargs("KAT_SEC_ALL") ? KAT_VECTOR_NUM : KAT_SEC_DEFAULT);

      display_test_results();

      $display("*** tessera_rsa_modexp simulation done. ***");
      $finish;
    end

endmodule // rsa_modexp_tb
