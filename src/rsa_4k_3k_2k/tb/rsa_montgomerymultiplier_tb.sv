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
// rsa_montgomerymultiplier_tb.sv
// ------------------------------
// Golden-product and latency checks for tessera_rsa_montgomerymultiplier.
// Based on src/ecc/tb/ecc_montgomerymultiplier_tb.sv; reports:
//
//     *** mm test processing time = N cycles.
//
// Vectors are produced by tb/rsa_montgomerymultiplier_model.py:
//     python3 rsa_montgomerymultiplier_model.py --gen 8 4096 32 <file>
//
// Override OPERAND_WIDTH to retarget the key size, e.g.
//     -pvalue+rsa_montgomerymultiplier_tb.OPERAND_WIDTH=3072
//
//======================================================================

// Mirror rtl/tessera_rsa_params_pkg.sv defines; the separate TB library cannot import
// it.  Override with e.g. +define+RSA_KEY_SIZE_CONFIG=3072.
`ifndef RSA_KEY_SIZE_CONFIG
  `define RSA_KEY_SIZE_CONFIG 4096
`endif
`ifndef RSA_RADIX_CONFIG
  `define RSA_RADIX_CONFIG 64
`endif

module rsa_montgomerymultiplier_tb #(
    parameter   OPERAND_WIDTH   = `RSA_KEY_SIZE_CONFIG,
    parameter   WORD_WIDTH      = `RSA_RADIX_CONFIG,
    parameter   TEST_VECTOR_NUM = 8,
    // Cover dual mode and unchanged single-lane full/half modes by default.
    // Override with -pvalue+rsa_montgomerymultiplier_tb.DUAL_EN_TB=0.
    parameter   DUAL_EN_TB      = 1
  )
  ();

  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  parameter CLK_HALF_PERIOD = 1;
  parameter CLK_PERIOD      = 2 * CLK_HALF_PERIOD;

  localparam                  STAT_CNT_WIDTH = 64;
  localparam  int unsigned    S_NUM   = ((OPERAND_WIDTH + WORD_WIDTH - 1) / WORD_WIDTH) + 1;
  // Montgomery radix width for optimized FIOS.
  localparam                  R_WIDTH = S_NUM * WORD_WIDTH + 1;
  localparam  int unsigned    FULL_REG_SIZE = S_NUM * WORD_WIDTH;

  // Expected latency of a single multiply, from the push_reg shift length.
  localparam  int unsigned    EXPECTED_MM_CYCLES = 3 * S_NUM;
  localparam  int unsigned    MOD_WORDS_TB = OPERAND_WIDTH / WORD_WIDTH;
  // Match the DUT's result-register count for zeroize checks.
  localparam  int unsigned    PE_UNITS = (S_NUM - 1) / 2 - 1;

  // Half-width sweep geometry, mirroring the DUT's *_H localparams.
  localparam  int unsigned    OPERAND_WIDTH_H      = OPERAND_WIDTH / 2;
  localparam  int unsigned    S_NUM_H              = ((OPERAND_WIDTH_H + WORD_WIDTH - 1) / WORD_WIDTH) + 1;
  localparam  int unsigned    EXPECTED_MM_CYCLES_H = 3 * S_NUM_H;

  //----------------------------------------------------------------
  // Type definitions
  //----------------------------------------------------------------
  typedef bit     [STAT_CNT_WIDTH-1:0]            stat_t;
  typedef bit     [OPERAND_WIDTH-1:0]             operand_t;
  typedef bit     [WORD_WIDTH-1:0]                word_t;
  typedef bit     [R_WIDTH-1:0]                   r_t;

  typedef struct packed {
      operand_t   a;
      operand_t   b;
      operand_t   n;
      r_t         n_prime;    // n' = -n^(-1) mod r requires R_WIDTH bits
      operand_t   product;
  } test_vector_t;

  //----------------------------------------------------------------
  // Register and Wire declarations.
  //----------------------------------------------------------------
  stat_t      cycle_ctr;
  stat_t      error_ctr;
  stat_t      tc_ctr;
  stat_t      start_time;
  stat_t      end_time;
  stat_t      min_time;
  stat_t      max_time;

  logic       clk_tb;
  logic       reset_n_tb;

  logic       start_man_tb;
  wire        start_i_tb;
  logic       zeroize_tb;
  logic       reduce_tb;
  logic       fwd_a_tb;
  logic       fwd_b_tb;
  logic       half_tb;
  logic       dual_tb;
  logic       accept_tb;

  // Overlapped squarings res = MM(res,res), paced by accept_o with both
  // operands forwarded, exercise two in-flight multiplies as in tessera_rsa_modexp.
  // Cycle-model goldens localize mismatches to individual multiplies.
  localparam int unsigned CHAIN_MAX = 64;
  logic       chain_en;
  int         chain_len_r;
  int         chain_launched;
  operand_t   chain_n;
  r_t         chain_np;
  operand_t   chain_seed;
  operand_t   chain_exp [CHAIN_MAX];
  int         chain_cnt;
  operand_t   opa_i_tb;
  operand_t   opb_i_tb;
  operand_t   n_i_tb;
  word_t      n_prime_i_tb;
  operand_t   p_o_tb;
  operand_t   opa1_i_tb;
  operand_t   opb1_i_tb;
  operand_t   n1_i_tb;
  word_t      n_prime1_i_tb;
  operand_t   p1_o_tb;
  logic       nonreducing_i_tb;
  logic [2*FULL_REG_SIZE-1:0] product_o_tb;
  logic       ready_tb;
  int         test_vector_cnt;

  test_vector_t test_vectors[TEST_VECTOR_NUM];

  // Launch directly on accept_o: an idle cycle changes MM_II parity and can
  // mask forwarding hazards.
  wire chain_fire = chain_en & accept_tb & (chain_launched < chain_len_r);
  assign start_i_tb = chain_en ? chain_fire : start_man_tb;

  always @(posedge clk_tb)
    if (chain_en & chain_fire)
      chain_launched <= chain_launched + 1;

  //----------------------------------------------------------------
  // Device Under Test.
  //----------------------------------------------------------------
  tessera_rsa_montgomerymultiplier #(
      .MODULUS_WIDTH  (OPERAND_WIDTH),
      .RADIX          (WORD_WIDTH),
      .DUAL_EN        (DUAL_EN_TB[0])
  )
  mm_dut (
      .clk        (clk_tb),
      .reset_n    (reset_n_tb),

      .start_i    (start_i_tb),
      .zeroize    (zeroize_tb),
      .opa_i      (opa_i_tb),
      .opb_i      (opb_i_tb),
      .n_i        (n_i_tb),
      .n_prime_i  (n_prime_i_tb),
      .nonreducing_i (nonreducing_i_tb),
      .reduce_i   (reduce_tb),
      .fwd_a_i    (fwd_a_tb),
      .fwd_b_i    (fwd_b_tb),
      .half_i     (half_tb),
      // Zero selects geometry from half_i.
      .geom_i     (8'd0),
      .dual_i     (dual_tb),
      .opa1_i     (opa1_i_tb[OPERAND_WIDTH/2-1:0]),
      .opb1_i     (opb1_i_tb[OPERAND_WIDTH/2-1:0]),
      .n1_i       (n1_i_tb[OPERAND_WIDTH/2-1:0]),
      .n_prime1_i (n_prime1_i_tb),
      .p_o        (p_o_tb),
      .p1_o       (p1_o_tb),
      .product_o  (product_o_tb),
      .ready_o    (ready_tb),
      .accept_o   (accept_tb)
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
      $display("");
    end
  endtask // reset_dut

  //----------------------------------------------------------------
  // display_test_results()
  //----------------------------------------------------------------
  task display_test_results;
    begin
      // Multiply latency must be independent of operand values.
      if (tc_ctr > 0 && min_time != max_time)
        begin
          $display("*** ERROR: latency is DATA DEPENDENT (min = %0d, max = %0d cycles).",
                   min_time, max_time);
          error_ctr = error_ctr + 1;
        end

      if (error_ctr == 0)
        begin
          $display("*** All %02d test cases completed successfully", tc_ctr);
          $display("* TESTCASE PASSED");
        end
      else
        begin
          $display("*** %02d tests completed - %02d test cases did not complete successfully.",
                   tc_ctr, error_ctr);
          $display("* TESTCASE FAILED");
        end
    end
  endtask // display_test_results

  //----------------------------------------------------------------
  // init_sim()
  //----------------------------------------------------------------
  task init_sim;
    begin
      cycle_ctr     = 0;
      error_ctr     = 0;
      tc_ctr        = 0;
      start_time    = 0;
      end_time      = 0;
      min_time      = '1;
      max_time      = 0;

      clk_tb        = 0;
      reset_n_tb    = 0;

      start_man_tb    = 0;
      zeroize_tb    = 0;
      opa_i_tb      = '0;
      opb_i_tb      = '0;
      n_i_tb        = '0;
      n_prime_i_tb  = '0;
      nonreducing_i_tb = 0;
      reduce_tb     = 1;
      fwd_a_tb      = 0;
      fwd_b_tb      = 0;
      half_tb       = 0;
      dual_tb       = 0;
      opa1_i_tb     = '0;
      opb1_i_tb     = '0;
      n1_i_tb       = '0;
      n_prime1_i_tb = '0;
      chain_en      = 0;
      chain_len_r   = 0;
      chain_launched = 0;
      chain_cnt     = 0;
    end
  endtask // init_sim

  //----------------------------------------------------------------
  // wait_ready()
  //----------------------------------------------------------------
  task wait_ready;
    begin
      while (ready_tb == 0)
        begin
            #CLK_PERIOD;
        end
    end
  endtask // wait_ready

  //----------------------------------------------------------------
  // mm_single_block_test()
  //----------------------------------------------------------------
  task mm_single_block_test(input [7 : 0]   tc_number,
                            input test_vector_t test_vector);
    begin
      $display("*** TC %0d mm test started.", tc_number);
      tc_ctr = tc_ctr + 1;

      opa_i_tb     = test_vector.a;
      opb_i_tb     = test_vector.b;
      n_i_tb       = test_vector.n;
      // The DUT uses only the low radix word of n_prime.
      n_prime_i_tb = test_vector.n_prime[WORD_WIDTH-1:0];

      #CLK_PERIOD;

      start_time = cycle_ctr;
      start_man_tb = 1;
      #CLK_PERIOD;

      start_man_tb = 0;
      wait_ready();
      end_time = cycle_ctr - start_time;

      $display("*** mm test processing time = %01d cycles.", end_time);

      if (end_time < min_time) min_time = end_time;
      if (end_time > max_time) max_time = end_time;

      if (p_o_tb == test_vector.product)
        begin
          $display("*** TC %0d successful.", tc_number);
          $display("");
        end
      else
        begin
          $display("*** ERROR: TC %0d NOT successful.", tc_number);
          $display("Expected: 0x%0x", test_vector.product);
          $display("Got:      0x%0x", p_o_tb);
          $display("");

          error_ctr = error_ctr + 1;
        end
    end
  endtask // mm_single_block_test

  //----------------------------------------------------------------
  // zeroize_test()
  //----------------------------------------------------------------
  // Interrupt a multiply with live secret-derived intermediates, then inspect
  // datapath registers for residue.  Aborting the FSM alone is insufficient.
  task zeroize_test(input test_vector_t tv);
    begin
      $display("*** zeroize test started.");
      tc_ctr = tc_ctr + 1;

      opa_i_tb     = tv.a;
      opb_i_tb     = tv.b;
      n_i_tb       = tv.n;
      n_prime_i_tb = tv.n_prime[WORD_WIDTH-1:0];

      start_man_tb = 1;
      #(CLK_PERIOD);
      start_man_tb = 0;

      // Zeroize while the array holds live intermediates.
      #(CLK_PERIOD * (EXPECTED_MM_CYCLES / 2));

      zeroize_tb = 1;
      #(CLK_PERIOD);
      zeroize_tb = 0;
      #(CLK_PERIOD);

      if (mm_dut.a_reg !== '0 || mm_dut.b_reg !== '0 ||
          mm_dut.p_reg !== '0 || mm_dut.n_prime_reg !== '0) begin
          $display("*** ERROR: zeroize left operand registers non-zero.");
          error_ctr = error_ctr + 1;
      end

      if (mm_dut.push_reg !== '0) begin
          $display("*** ERROR: zeroize did not abort the in-flight multiply.");
          error_ctr = error_ctr + 1;
      end

      for (int t = 0; t < 2*(PE_UNITS+1); t++) begin
          if (mm_dut.t_reg[t] !== '0 || mm_dut.t_subtracted_reg[t] !== '0) begin
              $display("*** ERROR: zeroize left result word %0d non-zero.", t);
              error_ctr = error_ctr + 1;
          end
      end

      if (mm_dut.last_s_reg !== '0) begin
          $display("*** ERROR: zeroize left last_s_reg non-zero.");
          error_ctr = error_ctr + 1;
      end

      // Verify recovery as well as erasure.
      #(CLK_PERIOD * 2);
      mm_single_block_test(0, tv);
    end
  endtask

  task mm_test;
      for (int i = 0; i < test_vector_cnt; i++) begin: test_vector_loop
          mm_single_block_test(i, test_vectors[i]);
      end
  endtask

  //----------------------------------------------------------------
  // mm_half_test()
  //
  // Check half_i against OPERAND_WIDTH/2 goldens and 3*S_NUM_H array latency.
  // Both the result and the shorter latency are required.
  //
  // Reuse the vector format with zero-extended operands; n_prime uses one
  // radix word at either width.
  //----------------------------------------------------------------
  task mm_half_test;
      string  hname;
      int     saved_cnt;
      integer probe;
      begin
          hname = $sformatf("rsa_mm_test_vectors_%0d_key_%0d_word_%0d.hex",
                            TEST_VECTOR_NUM, OPERAND_WIDTH_H, WORD_WIDTH);

          // Report missing half-width goldens as a coverage skip.
          probe = $fopen(hname, "r");
          if (probe == 0) begin
              $display("*** SKIP: half-width sweep test -- no golden vectors %s.", hname);
              disable mm_half_test;
          end
          $fclose(probe);

          $display("*** half-width sweep test started (key %0d -> %0d, expected latency %0d cycles).",
                   OPERAND_WIDTH, OPERAND_WIDTH_H, EXPECTED_MM_CYCLES_H + 1);

          read_test_vectors(hname);
          saved_cnt = test_vector_cnt;

          half_tb = 1;
          for (int i = 0; i < saved_cnt; i++) begin : half_vector_loop
              tc_ctr = tc_ctr + 1;

              opa_i_tb     = test_vectors[i].a;
              opb_i_tb     = test_vectors[i].b;
              n_i_tb       = test_vectors[i].n;
              n_prime_i_tb = test_vectors[i].n_prime[WORD_WIDTH-1:0];

              #CLK_PERIOD;

              start_time   = cycle_ctr;
              start_man_tb = 1;
              #CLK_PERIOD;
              start_man_tb = 0;
              wait_ready();
              end_time = cycle_ctr - start_time;

              // Start-to-ready sampling adds one cycle to the push_reg shift
              // length in both full and half modes.
              if (end_time != EXPECTED_MM_CYCLES_H + 1) begin
                  $display("*** ERROR: half TC %0d latency = %0d cycles, expected %0d.",
                           i, end_time, EXPECTED_MM_CYCLES_H + 1);
                  error_ctr = error_ctr + 1;
              end

              if (p_o_tb == test_vectors[i].product) begin
                  $display("*** half TC %0d successful (%0d cycles).", i, end_time);
              end
              else begin
                  $display("*** ERROR: half TC %0d NOT successful.", i);
                  $display("Expected: 0x%0x", test_vectors[i].product);
                  $display("Got:      0x%0x", p_o_tb);
                  error_ctr = error_ctr + 1;
              end
          end
          half_tb = 0;

          // Restore full-width operands for later tasks, including zeroize_test.
          read_test_vectors($sformatf("rsa_mm_test_vectors_%0d_key_%0d_word_%0d.hex",
                                      TEST_VECTOR_NUM, OPERAND_WIDTH, WORD_WIDTH));
      end
  endtask

  //----------------------------------------------------------------
  // mm_dual_test()
  //
  // Two half-width lanes share launch, odd phase and retirement.
  // Pair half-width vectors i and (i+1) mod count so differing moduli and
  // n_prime values expose cross-lane coupling.
  //
  // Check both products and the single-half-width latency: 3*S_NUM_H cycles
  // plus the TB's one-cycle sampling offset.
  //----------------------------------------------------------------
  task mm_dual_test;
      string        hname;
      int           saved_cnt;
      integer       probe;
      test_vector_t hv [TEST_VECTOR_NUM];
      int           l1;
      begin
          if (DUAL_EN_TB == 0) begin
              $display("*** SKIP: dual-lane test -- DUT built with DUAL_EN = 0.");
              disable mm_dual_test;
          end

          hname = $sformatf("rsa_mm_test_vectors_%0d_key_%0d_word_%0d.hex",
                            TEST_VECTOR_NUM, OPERAND_WIDTH_H, WORD_WIDTH);

          probe = $fopen(hname, "r");
          if (probe == 0) begin
              $display("*** SKIP: dual-lane test -- no golden vectors %s.", hname);
              disable mm_dual_test;
          end
          $fclose(probe);

          $display("*** dual-lane test started (2 x %0d-bit lanes, expected latency %0d cycles).",
                   OPERAND_WIDTH_H, EXPECTED_MM_CYCLES_H + 1);

          read_test_vectors(hname);
          saved_cnt = test_vector_cnt;
          for (int i = 0; i < saved_cnt; i++)
              hv[i] = test_vectors[i];

          dual_tb = 1;
          for (int i = 0; i < saved_cnt; i++) begin : dual_vector_loop
              l1 = (i + 1) % saved_cnt;
              tc_ctr = tc_ctr + 1;

              opa_i_tb      = hv[i].a;
              opb_i_tb      = hv[i].b;
              n_i_tb        = hv[i].n;
              n_prime_i_tb  = hv[i].n_prime[WORD_WIDTH-1:0];

              opa1_i_tb     = hv[l1].a;
              opb1_i_tb     = hv[l1].b;
              n1_i_tb       = hv[l1].n;
              n_prime1_i_tb = hv[l1].n_prime[WORD_WIDTH-1:0];

              #CLK_PERIOD;

              start_time   = cycle_ctr;
              start_man_tb = 1;
              #CLK_PERIOD;
              start_man_tb = 0;
              wait_ready();
              end_time = cycle_ctr - start_time;

              if (end_time != EXPECTED_MM_CYCLES_H + 1) begin
                  $display("*** ERROR: dual TC %0d latency = %0d cycles, expected %0d.",
                           i, end_time, EXPECTED_MM_CYCLES_H + 1);
                  error_ctr = error_ctr + 1;
              end

              if ((p_o_tb == hv[i].product) && (p1_o_tb == hv[l1].product)) begin
                  $display("*** dual TC %0d successful (%0d cycles).", i, end_time);
              end
              else begin
                  $display("*** ERROR: dual TC %0d NOT successful.", i);
                  $display("lane0 expected: 0x%0x", hv[i].product);
                  $display("lane0 got:      0x%0x", p_o_tb);
                  $display("lane1 expected: 0x%0x", hv[l1].product);
                  $display("lane1 got:      0x%0x", p1_o_tb);
                  error_ctr = error_ctr + 1;
              end
          end
          dual_tb = 0;
          opa1_i_tb     = '0;
          opb1_i_tb     = '0;
          n1_i_tb       = '0;
          n_prime1_i_tb = '0;

          // Restore the full-width vector set for the tasks that follow.
          read_test_vectors($sformatf("rsa_mm_test_vectors_%0d_key_%0d_word_%0d.hex",
                                      TEST_VECTOR_NUM, OPERAND_WIDTH, WORD_WIDTH));
      end
  endtask

  //----------------------------------------------------------------
  // mm_smallmod_test()
  //
  // Full-width multiply against a half-width odd modulus, as needed for CRT
  // base reduction.  Half mode would truncate a full-width x rather than
  // reduce it mod p.  The conversion uses:
  //
  //     s1 = MM_full(x,  R_half^2 mod p) = x * 2^RADIX mod p
  //     s2 = MM_half(s1, R_full  mod p)  = x * R_half  mod p
  //
  // R_half^2 = R_full * 2^RADIX since S_NUM = 2*S_NUM_H - 1 at supported sizes.
  // s2 is the half-width ladder's Montgomery base.
  //
  // This tests only step 1's geometry: n is zero-extended and n_prime still
  // depends on its low word.  Require full-width 3*S_NUM array latency
  // (plus one TB sampling cycle), with no shortcut for the narrow modulus.
  //----------------------------------------------------------------
  task mm_smallmod_test;
        string  sname;
        int     saved_cnt;
        integer probe;
        begin
            sname = $sformatf("rsa_mm_smallmod_vectors_%0d_key_%0d_word_%0d.hex",
                              TEST_VECTOR_NUM, OPERAND_WIDTH, WORD_WIDTH);

            probe = $fopen(sname, "r");
            if (probe == 0) begin
                $display("*** SKIP: small-modulus test -- no golden vectors %s.", sname);
                disable mm_smallmod_test;
            end
            $fclose(probe);

            $display("*** small-modulus test started (full width %0d, modulus %0d bits, expected latency %0d cycles).",
                     OPERAND_WIDTH, OPERAND_WIDTH_H, EXPECTED_MM_CYCLES + 1);

            read_test_vectors(sname);
            saved_cnt = test_vector_cnt;

            // Keep full-width geometry despite the narrow modulus.
            for (int i = 0; i < saved_cnt; i++) begin : smallmod_vector_loop
                tc_ctr = tc_ctr + 1;

                opa_i_tb     = test_vectors[i].a;
                opb_i_tb     = test_vectors[i].b;
                n_i_tb       = test_vectors[i].n;
                n_prime_i_tb = test_vectors[i].n_prime[WORD_WIDTH-1:0];

                #CLK_PERIOD;

                start_time   = cycle_ctr;
                start_man_tb = 1;
                #CLK_PERIOD;
                start_man_tb = 0;
                wait_ready();
                end_time = cycle_ctr - start_time;

                if (end_time != EXPECTED_MM_CYCLES + 1) begin
                    $display("*** ERROR: smallmod TC %0d latency = %0d cycles, expected %0d.",
                             i, end_time, EXPECTED_MM_CYCLES + 1);
                    error_ctr = error_ctr + 1;
                end

                if (p_o_tb == test_vectors[i].product) begin
                    $display("*** smallmod TC %0d successful (%0d cycles).", i, end_time);
                end
                else begin
                    $display("*** ERROR: smallmod TC %0d NOT successful.", i);
                    $display("Expected: 0x%0x", test_vectors[i].product);
                    $display("Got:      0x%0x", p_o_tb);
                    error_ctr = error_ctr + 1;
                end
            end

            // Restore the full-width vector set for any later task.
            read_test_vectors($sformatf("rsa_mm_test_vectors_%0d_key_%0d_word_%0d.hex",
                                        TEST_VECTOR_NUM, OPERAND_WIDTH, WORD_WIDTH));
        end
  endtask

  task read_test_vectors(input string fname);
      integer values_per_test_vector;
      integer line_cnt;
      integer fin;
      integer rv;
      r_t val;    // must be the largest width of any possible value
      test_vector_t test_vector;

      // Match the six fields from rsa_montgomerymultiplier_model.py --gen.
      values_per_test_vector = 6;
      line_cnt = 0;
      test_vector_cnt = 0;

      fin = $fopen(fname, "r");
      if (fin == 0)
          $error("Can't open file %s", fname);
      while (!$feof(fin)) begin
          rv = $fscanf(fin, "%h\n", val);
          if (rv != 1) begin
              $error("Failed to read a matching string");
              $fclose(fin);
              $finish;
          end
          case (line_cnt % values_per_test_vector)
              0: test_vector.a            = val;
              1: test_vector.b            = val;
              2: test_vector.n            = val;
              3: test_vector.n_prime      = val;
              4: begin
                 test_vector.product      = val;
                 test_vectors[test_vector_cnt] = test_vector;
              end
              5 : test_vector_cnt++;
          endcase

          line_cnt++;
      end
      $fclose(fin);

      $display("Read %0d test vectors from %s", test_vector_cnt, fname);
  endtask

  //----------------------------------------------------------------
  // nonreducing_single()
  //
  // Check the full 2N product against behavioral multiplication.  Invalid
  // n_i/n_prime_i values test independence from the modulus context.
  //----------------------------------------------------------------
  task nonreducing_single(input string name,
                          input [OPERAND_WIDTH-1:0] a,
                          input [OPERAND_WIDTH-1:0] b);
    logic [2*FULL_REG_SIZE-1:0] expected;
    int unsigned latency;
    begin
      tc_ctr = tc_ctr + 1;
      expected = {{FULL_REG_SIZE{1'b0}}, {(FULL_REG_SIZE-OPERAND_WIDTH){1'b0}}, a} *
                 {{FULL_REG_SIZE{1'b0}}, {(FULL_REG_SIZE-OPERAND_WIDTH){1'b0}}, b};

      opa_i_tb         = a;
      opb_i_tb         = b;
      nonreducing_i_tb = 1;
      #(CLK_PERIOD);
      start_time = cycle_ctr;
      start_man_tb = 1;
      #(CLK_PERIOD);
      start_man_tb = 0;
      wait_ready();
      end_time = cycle_ctr - start_time;
      latency  = end_time;

      if (product_o_tb !== expected)
        begin
          $display("*** ERROR: nonreducing %s product mismatch.", name);
          $display("    expected %h", expected);
          $display("    got      %h", product_o_tb);
          error_ctr = error_ctr + 1;
        end
      else
        $display("*** nonreducing %s OK (%0d cycles).", name, latency);

      // Match reducing latency measured by the preceding mm_test.
      if (latency != min_time)
        begin
          $display("*** ERROR: nonreducing %s latency %0d, reducing multiply takes %0d.",
                   name, latency, min_time);
          error_ctr = error_ctr + 1;
        end
      nonreducing_i_tb = 0;
    end
  endtask // nonreducing_single

  //----------------------------------------------------------------
  // nonreducing_test()
  //----------------------------------------------------------------
  task nonreducing_test;
    logic [OPERAND_WIDTH-1:0] a, b;
    begin
      $display("*** Non-reducing (plain integer multiply) tests started.");
      // MUL must ignore this invalid modulus context.
      n_i_tb       = '0;
      n_prime_i_tb = '1;

      nonreducing_single("zero", '0, '0);
      nonreducing_single("one", {{(OPERAND_WIDTH-1){1'b0}}, 1'b1},
                                {{(OPERAND_WIDTH-1){1'b0}}, 1'b1});
      nonreducing_single("all ones", '1, '1);

      for (int t = 0; t < 4; t++)
        begin
          for (int w = 0; w < (OPERAND_WIDTH/32); w++)
            begin
              a[w*32 +: 32] = $urandom();
              b[w*32 +: 32] = $urandom();
            end
          nonreducing_single($sformatf("random %0d", t), a, b);
        end
      $display("*** Non-reducing tests done.");
      $display("");
    end
  endtask // nonreducing_test


  //----------------------------------------------------------------
  // read_chain_vectors()
  //
  // rsa_montgomerymultiplier_model.py --gen-chain emits one hex value per line:
  // n, n_prime, seed, then expected products p[0] .. p[k-1] with reduce_i = 0.
  //----------------------------------------------------------------
  task read_chain_vectors(input string fname);
    integer fin;
    integer rv;
    integer idx;
    r_t     val;
    begin
      chain_cnt = 0;
      idx       = 0;
      fin = $fopen(fname, "r");
      if (fin == 0) begin
          $display("*** ERROR: can't open chain vector file %s", fname);
          error_ctr = error_ctr + 1;
          disable read_chain_vectors;
      end
      while (!$feof(fin)) begin
          rv = $fscanf(fin, "%h\n", val);
          if (rv != 1)
              break;
          case (idx)
              0: chain_n    = val[OPERAND_WIDTH-1:0];
              1: chain_np   = val;
              2: chain_seed = val[OPERAND_WIDTH-1:0];
              default: begin
                  if (chain_cnt < CHAIN_MAX) begin
                      chain_exp[chain_cnt] = val[OPERAND_WIDTH-1:0];
                      chain_cnt = chain_cnt + 1;
                  end
              end
          endcase
          idx = idx + 1;
      end
      $fclose(fin);
      $display("Read a %0d-deep MM chain from %s", chain_cnt, fname);
    end
  endtask // read_chain_vectors

  //----------------------------------------------------------------
  // mm_chain_test()
  //
  // Check every retirement of accept_o-paced squarings with both operands
  // forwarded.  Requires pipelining; without it the forwarding bits are ignored.
  //----------------------------------------------------------------
  task mm_chain_test(input int klen, input bit half);
    int unsigned kn;
    int unsigned exp_ii;
    int unsigned got;
    int unsigned prev_ready;
    int unsigned this_ready;
    int unsigned chain_ii;
    int unsigned guard;
    int lo_bad;
    int hi_bad;
    int bad_n;
    begin
      guard = 0;
      kn = ((klen <= 0) || (klen > chain_cnt)) ? chain_cnt : klen;
      if (chain_cnt < 2) begin
          $display("*** chain test skipped (no vectors).");
          disable mm_chain_test;
      end
      exp_ii = half ? mm_dut.MM_II_H : mm_dut.MM_II;
      $display("*** Overlapped forwarding chain test started (%0d of %0d multiplies, half=%0d, expected II = %0d).",
               kn, chain_cnt, half, exp_ii);

      // Keep half stable across launches because the array shares half_reg.
      half_tb          = half;
      n_i_tb           = chain_n;
      n_prime_i_tb     = chain_np[WORD_WIDTH-1:0];
      nonreducing_i_tb = 0;
      reduce_tb        = 0;
      // The first multiply has no producer to forward from.
      opa_i_tb         = chain_seed;
      opb_i_tb         = chain_seed;
      fwd_a_tb         = 0;
      fwd_b_tb         = 0;
      chain_launched   = 0;
      chain_len_r      = kn;

      // Manually launch the head: accept_o stays low until the first start_i,
      // as in tessera_rsa_modexp.
      @(negedge clk_tb);
      start_man_tb = 1;
      @(negedge clk_tb);
      start_man_tb = 0;
      // Subsequent launches follow accept_o at exactly MM_II.
      fwd_a_tb = 1;
      fwd_b_tb = 1;
      // Poison operand ports to detect reads that bypass forwarding.
      opa_i_tb = '1;
      opb_i_tb = '1;
      chain_launched = 1;
      chain_en = 1;

      got        = 0;
      prev_ready = 0;
      chain_ii   = 0;
      while (got < kn) begin
          @(posedge clk_tb);
          guard = guard + 1;
          if (guard > (kn + 4) * EXPECTED_MM_CYCLES) begin
              $display("*** ERROR: chain test hung after %0d retirements (no ready_o).", got);
              error_ctr = error_ctr + 1;
              chain_en = 0;
              disable mm_chain_test;
          end
          if (ready_tb) begin
              this_ready = cycle_ctr;
              tc_ctr = tc_ctr + 1;
              #(CLK_PERIOD);        // let p_o settle on the final word
              if (p_o_tb !== chain_exp[got]) begin
                  error_ctr = error_ctr + 1;
                  if (error_ctr < 8) begin
                      // Map bad word w to PE stage w>>1 to localize overlap faults.
                      lo_bad = -1;
                      hi_bad = -1;
                      bad_n  = 0;
                      for (int w = 0; w < MOD_WORDS_TB; w++) begin
                          if (p_o_tb[w*WORD_WIDTH +: WORD_WIDTH] !==
                              chain_exp[got][w*WORD_WIDTH +: WORD_WIDTH]) begin
                              if (lo_bad < 0) lo_bad = w;
                              hi_bad = w;
                              bad_n  = bad_n + 1;
                          end
                      end
                      $display("*** ERROR: chain multiply %0d mismatch.", got);
                      $display("    bad words: %0d of %0d, lowest=%0d (PE stage %0d), highest=%0d (PE stage %0d)",
                               bad_n, MOD_WORDS_TB, lo_bad, lo_bad/2, hi_bad, hi_bad/2);
                      if (lo_bad >= 0)
                          $display("    word %0d: expected 0x%0x got 0x%0x", lo_bad,
                                   chain_exp[got][lo_bad*WORD_WIDTH +: WORD_WIDTH],
                                   p_o_tb[lo_bad*WORD_WIDTH +: WORD_WIDTH]);
                  end
              end
              else
                  $display("    chain multiply %0d OK", got);
              if (got > 0) begin
                  if (chain_ii == 0)
                      chain_ii = this_ready - prev_ready;
                  else if ((this_ready - prev_ready) != chain_ii) begin
                      $display("*** ERROR: chain II is DATA DEPENDENT (%0d vs %0d).",
                               this_ready - prev_ready, chain_ii);
                      error_ctr = error_ctr + 1;
                  end
              end
              prev_ready = this_ready;
              got = got + 1;
          end
      end
      chain_en = 0;
      fwd_a_tb = 0;
      fwd_b_tb = 0;
      half_tb  = 0;
      reduce_tb = 1;

      // Check the expected II as well as its data independence.
      if (chain_ii != exp_ii) begin
          $display("*** ERROR: chain II = %0d cycles, expected %0d.", chain_ii, exp_ii);
          error_ctr = error_ctr + 1;
      end
      // Posedge sampling exits half a cycle off the vector tasks' phase.
      // Realign to whole CLK_PERIOD boundaries to avoid subsequent DUT races.
      while (($time % CLK_PERIOD) != 0)
          #(CLK_PERIOD/2);
      $display("*** Chain test done.  Measured II = %0d cycles (single-multiply latency = %0d).",
               chain_ii, EXPECTED_MM_CYCLES);
      $display("");
    end
  endtask // mm_chain_test

  //----------------------------------------------------------------
  // mm_half_chain_test()
  //
  // Exercise half-width forwarding with two multiplies in flight, not just
  // isolated multiplies.  accept_o paces launches while half_reg stays fixed;
  // require the half-width II of 2*S_NUM_H+2.
  //----------------------------------------------------------------
  task mm_half_chain_test;
      string  cname;
      integer probe;
      begin
          cname = $sformatf("rsa_mm_chain_vectors_key_%0d_word_%0d.hex",
                            OPERAND_WIDTH_H, WORD_WIDTH);
          probe = $fopen(cname, "r");
          if (probe == 0) begin
              $display("*** SKIP: half-width chain test -- no golden vectors %s.", cname);
              disable mm_half_chain_test;
          end
          $fclose(probe);

          read_chain_vectors(cname);
          mm_chain_test(0, 1'b1);

          // Restore the full-width chain context for anything that runs later.
          read_chain_vectors($sformatf("rsa_mm_chain_vectors_key_%0d_word_%0d.hex",
                                       OPERAND_WIDTH, WORD_WIDTH));
      end
  endtask

  //----------------------------------------------------------------
  // mm_dual_chain_test()
  //
  // Exercise both lanes' forwarding taps, including t_reg[LANE1_W0 + q]
  // for lane 1, which isolated dual multiplies do not cover.
  //
  // Start lane 1 one squaring ahead in the same chain: expected retirements
  // are chain_exp[k] and chain_exp[k+1].  Distinct data exposes crossed taps.
  //
  // Require two results per MM_II_H interval, not the full-width MM_II.
  //----------------------------------------------------------------
  task mm_dual_chain_test;
      string        cname;
      integer       probe;
      int unsigned  kn;
      int unsigned  exp_ii;
      int unsigned  got;
      int unsigned  prev_ready;
      int unsigned  this_ready;
      int unsigned  chain_ii;
      int unsigned  guard;
      begin
          if (DUAL_EN_TB == 0) begin
              $display("*** SKIP: dual chain test -- DUT built with DUAL_EN = 0.");
              disable mm_dual_chain_test;
          end

          cname = $sformatf("rsa_mm_chain_vectors_key_%0d_word_%0d.hex",
                            OPERAND_WIDTH_H, WORD_WIDTH);
          probe = $fopen(cname, "r");
          if (probe == 0) begin
              $display("*** SKIP: dual chain test -- no golden vectors %s.", cname);
              disable mm_dual_chain_test;
          end
          $fclose(probe);

          read_chain_vectors(cname);
          if (chain_cnt < 3) begin
              $display("*** SKIP: dual chain test -- chain too short (%0d).", chain_cnt);
              read_chain_vectors($sformatf("rsa_mm_chain_vectors_key_%0d_word_%0d.hex",
                                           OPERAND_WIDTH, WORD_WIDTH));
              disable mm_dual_chain_test;
          end

          // Lane 1 is offset by one, so it consumes one more golden than lane 0.
          kn     = chain_cnt - 1;
          exp_ii = mm_dut.MM_II_H;
          guard  = 0;
          $display("*** Dual-lane forwarding chain test started (%0d multiplies per lane, expected II = %0d).",
                   kn, exp_ii);

          half_tb          = 0;   // dual implies half inside the DUT
          dual_tb          = 1;
          nonreducing_i_tb = 0;
          reduce_tb        = 0;
          n_i_tb           = chain_n;
          n_prime_i_tb     = chain_np[WORD_WIDTH-1:0];
          n1_i_tb          = chain_n;
          n_prime1_i_tb    = chain_np[WORD_WIDTH-1:0];
          opa_i_tb         = chain_seed;
          opb_i_tb         = chain_seed;
          opa1_i_tb        = chain_exp[0];   // lane 1 starts one step ahead
          opb1_i_tb        = chain_exp[0];
          fwd_a_tb         = 0;
          fwd_b_tb         = 0;
          chain_launched   = 0;
          chain_len_r      = kn;

          @(negedge clk_tb);
          start_man_tb = 1;
          @(negedge clk_tb);
          start_man_tb = 0;
          fwd_a_tb = 1;
          fwd_b_tb = 1;
          // Poison all operand ports to detect reads that bypass forwarding.
          opa_i_tb  = '1;
          opb_i_tb  = '1;
          opa1_i_tb = '1;
          opb1_i_tb = '1;
          chain_launched = 1;
          chain_en = 1;

          got        = 0;
          prev_ready = 0;
          chain_ii   = 0;
          while (got < kn) begin
              @(posedge clk_tb);
              guard = guard + 1;
              if (guard > (kn + 4) * EXPECTED_MM_CYCLES) begin
                  $display("*** ERROR: dual chain test hung after %0d retirements.", got);
                  error_ctr = error_ctr + 1;
                  chain_en = 0;
                  disable mm_dual_chain_test;
              end
              if (ready_tb) begin
                  this_ready = cycle_ctr;
                  tc_ctr = tc_ctr + 1;
                  #(CLK_PERIOD);
                  if ((p_o_tb !== chain_exp[got]) || (p1_o_tb !== chain_exp[got+1])) begin
                      error_ctr = error_ctr + 1;
                      if (error_ctr < 8) begin
                          $display("*** ERROR: dual chain multiply %0d mismatch.", got);
                          $display("    lane0 expected: 0x%0x", chain_exp[got]);
                          $display("    lane0 got:      0x%0x", p_o_tb);
                          $display("    lane1 expected: 0x%0x", chain_exp[got+1]);
                          $display("    lane1 got:      0x%0x", p1_o_tb);
                      end
                  end
                  else
                      $display("    dual chain multiply %0d OK (both lanes)", got);
                  if (got > 0) begin
                      if (chain_ii == 0)
                          chain_ii = this_ready - prev_ready;
                      else if ((this_ready - prev_ready) != chain_ii) begin
                          $display("*** ERROR: dual chain II is DATA DEPENDENT (%0d vs %0d).",
                                   this_ready - prev_ready, chain_ii);
                          error_ctr = error_ctr + 1;
                      end
                  end
                  prev_ready = this_ready;
                  got = got + 1;
              end
          end
          chain_en  = 0;
          fwd_a_tb  = 0;
          fwd_b_tb  = 0;
          dual_tb   = 0;
          reduce_tb = 1;
          opa1_i_tb     = '0;
          opb1_i_tb     = '0;
          n1_i_tb       = '0;
          n_prime1_i_tb = '0;

          if (chain_ii != exp_ii) begin
              $display("*** ERROR: dual chain II = %0d cycles, expected %0d.", chain_ii, exp_ii);
              error_ctr = error_ctr + 1;
          end
          // Realign to the whole-CLK_PERIOD stimulus phase the vector tasks use.
          while (($time % CLK_PERIOD) != 0)
              #(CLK_PERIOD/2);
          $display("*** Dual chain test done.  Measured II = %0d cycles.", chain_ii);
          $display("");

          // Restore the full-width chain context for anything that runs later.
          read_chain_vectors($sformatf("rsa_mm_chain_vectors_key_%0d_word_%0d.hex",
                                       OPERAND_WIDTH, WORD_WIDTH));
      end
  endtask // mm_dual_chain_test

  //----------------------------------------------------------------
  // main
  //----------------------------------------------------------------
  initial
    begin : main
      string fname;

      $display("   -= Testbench for tessera_rsa_montgomerymultiplier started =-");
      $display("    =================================================\n");
      $display("*** CONFIG: KEY_SIZE = %0d, RADIX = %0d, S_NUM = %0d, expected latency = %0d cycles.",
               OPERAND_WIDTH, WORD_WIDTH, S_NUM, EXPECTED_MM_CYCLES);

      fname = $sformatf("rsa_mm_test_vectors_%0d_key_%0d_word_%0d.hex",
                        TEST_VECTOR_NUM, OPERAND_WIDTH, WORD_WIDTH);

      read_test_vectors(fname);

      init_sim();
      read_chain_vectors($sformatf("rsa_mm_chain_vectors_key_%0d_word_%0d.hex",
                                   OPERAND_WIDTH, WORD_WIDTH));
      reset_dut();

      // Establish a baseline before the chain to distinguish pre-existing failures.
      mm_test();
      reset_dut();
`ifndef RSA_MM_NO_PIPELINE
      // Non-pipelined mode ignores forwarding and would read poisoned operands.
      mm_chain_test(2, 1'b0);   // two deep: no successor to disturb multiply 1
      reset_dut();
      mm_chain_test(0, 1'b0);   // full depth
      reset_dut();
      mm_half_chain_test();
      reset_dut();
      mm_dual_chain_test();
      reset_dut();
`endif
      mm_test();
      reset_dut();
      mm_half_test();
      reset_dut();
      mm_dual_test();
      reset_dut();
      mm_smallmod_test();
      reset_dut();
      nonreducing_test();
      zeroize_test(test_vectors[0]);

      display_test_results();

      $display("");
      $display("*** tessera_rsa_montgomerymultiplier simulation done. ***");
      $finish;
    end // main

endmodule // rsa_montgomerymultiplier_tb
