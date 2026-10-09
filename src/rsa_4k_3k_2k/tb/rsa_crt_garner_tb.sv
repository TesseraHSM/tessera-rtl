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
// rsa_crt_garner_tb.sv
// --------------------
// Check Garner recombination using tessera_rsa_modexp's real request/done handshake.
//
// Require golden results and equal latency across vectors.  All inputs
// (p, q, qinv, m1, m2) are secret; reducing m1 + 2p - m2 into [0, p)
// must not introduce data-dependent timing.
//
// rsa_crt_garner_vector_gen.py checks each golden m against m % p == m1
// and m % q == m2, independently of Garner's formula.
//
//======================================================================

`ifndef RSA_KEY_SIZE_CONFIG
  `define RSA_KEY_SIZE_CONFIG 4096
`endif
`ifndef RSA_RADIX_CONFIG
  `define RSA_RADIX_CONFIG 64
`endif

module rsa_crt_garner_tb;

  localparam int unsigned KEY_SIZE      = `RSA_KEY_SIZE_CONFIG;
  localparam int unsigned RADIX         = `RSA_RADIX_CONFIG;
  localparam int unsigned NWORDS        = KEY_SIZE / RADIX;
  localparam int unsigned S_NUM         = NWORDS + 1;
  localparam int unsigned FULL_REG_SIZE = S_NUM * RADIX;
  localparam int unsigned VECTOR_NUM    = 4;

  localparam string VECTOR_FILE =
      $sformatf("rsa_crt_garner_vectors_%0d_key_%0d_word_%0d.hex",
                VECTOR_NUM, KEY_SIZE, RADIX);

  logic                     clk = 0;
  logic                     rst_n = 0;
  logic                     zeroize = 0;
  logic                     start = 0;

  logic [KEY_SIZE-1:0]      p, q, qinv, r2_p, m1, m2;
  logic [RADIX-1:0]         n_prime;
  logic [KEY_SIZE-1:0]      result;
  logic                     done, busy;

  logic                     mm_req, mul_req, mm_half;
  logic [KEY_SIZE-1:0]      mm_a, mm_b;
  logic                     mm_done;
  logic [KEY_SIZE-1:0]      mm_result;
  logic [2*FULL_REG_SIZE-1:0] mm_product;

  int unsigned              errors = 0;
  int unsigned              cycle_count;
  int unsigned              min_cycles, max_cycles;

  always #5 clk = ~clk;

  tessera_rsa_crt_garner #(
      .MODULUS_BIT_WIDTH (KEY_SIZE),
      .WORD_BIT_WIDTH    (RADIX)
  ) dut (
      .clk                 (clk),
      .rst_n               (rst_n),
      .zeroize             (zeroize),
      .start_in            (start),
      .m1_in               (m1),
      .m2_in               (m2),
      .p_in                (p),
      .q_in                (q),
      .qinv_in             (qinv),
      .r_pow_2_mod_p_in    (r2_p),
      .mm_req_out          (mm_req),
      .mul_req_out         (mul_req),
      .mm_half_out         (mm_half),
      .mm_a_out            (mm_a),
      .mm_b_out            (mm_b),
      .mm_done_in          (mm_done),
      .mm_result_in        (mm_result),
      .mul_product_in      (mm_product[2*KEY_SIZE-1:0]),
      .result_out          (result),
      .done_out            (done),
      .busy_out            (busy)
  );

  // Requests are mutually exclusive; mul_mode has priority in tessera_rsa_modexp.
  // All recombination reductions use the same modulus context p.
  tessera_rsa_modexp #(
      .MODULUS_BIT_WIDTH  (KEY_SIZE),
      .EXPONENT_BIT_WIDTH (KEY_SIZE),
      .WORD_BIT_WIDTH     (RADIX)
  ) mm_servicer (
      .clk                   (clk),
      .rst_n                 (rst_n),
      .start_in              (mm_req | mul_req),
      .zeroize               (zeroize),
      .mul_mode_in           (mul_req),
      .mm_mode_in            (mm_req),
      .mm_half_in            (mm_half),
      .mm_geom_in            (8'd0),
      .mm_sq_rep_in          (6'd0),
      // The ladder is never used here.
      .half_in               (1'b0),
      .geom_in               (8'd0),
      .mul_b_in              (mm_b),
      .base_in               (mm_a),
      .exponent_in           ('0),
      .exponent_msb_index_in ('0),
      .exp_public_in         (1'b0),
      .n_in                  (p),
      .n_prime_lsw_in        (n_prime),
      .r_pow_1_mod_n_in      ('0),
      .r_pow_2_mod_n_in      ('0),
      // Tie off unbuilt lane 1 (DUAL_EN=0) to avoid VCS Warning-[TFIPC].
      .dual_in               (1'b0),
      .base1_in              ('0),
      .exponent1_in          ('0),
      .n1_in                 ('0),
      .n_prime1_lsw_in       ('0),
      .r_pow_1_mod_n1_in     ('0),
      .r_pow_2_mod_n1_in     ('0),
      .mul_b1_in             ('0),
      .result_out            (mm_result),
      .result1_out           (),
      .product_out           (mm_product),
      .done_out              (mm_done)
  );

  task automatic run_vector(input int idx,
                            input logic [KEY_SIZE-1:0] exp_m);
    begin
      start = 1;
      @(posedge clk);
      start = 0;
      cycle_count = 0;
      while (!done) begin
        @(posedge clk);
        cycle_count++;
      end

      if (result !== exp_m) begin
        errors++;
        $display("ERROR: vector %0d recombination mismatch", idx);
        $display("  expected %h", exp_m);
        $display("  got      %h", result);
      end

      if (cycle_count < min_cycles) min_cycles = cycle_count;
      if (cycle_count > max_cycles) max_cycles = cycle_count;

      @(posedge clk);
    end
  endtask

  initial begin : main
    integer fin, rv, i;
    logic [KEY_SIZE-1:0] exp_m;
    logic [KEY_SIZE-1:0] np_wide;

    $display("   -= Testbench for tessera_rsa_crt_garner started =-");
    $display("    ========================================\n");
    $display("*** CONFIG: KEY_SIZE = %0d, RADIX = %0d, half = %0d bits.",
             KEY_SIZE, RADIX, KEY_SIZE/2);

    min_cycles = 32'hFFFF_FFFF;
    max_cycles = 0;

    rst_n = 0;
    repeat (4) @(posedge clk);
    rst_n = 1;
    repeat (2) @(posedge clk);

    fin = $fopen(VECTOR_FILE, "r");
    if (fin == 0) begin
      $display("*** ERROR: can't open vector file %0s", VECTOR_FILE);
      $display("***        Generate with: python3 rsa_crt_garner_vector_gen.py %0d %0d %0d",
               VECTOR_NUM, KEY_SIZE, RADIX);
      $display("* TESTCASE FAILED");
      $finish;
    end

    for (i = 0; i < VECTOR_NUM; i++) begin
      rv = $fscanf(fin, "%h %h %h %h %h %h %h %h\n",
                   p, q, qinv, np_wide, r2_p, m1, m2, exp_m);
      if (rv != 8) begin
        $display("*** ERROR: %0s truncated at vector %0d (read %0d fields).",
                 VECTOR_FILE, i, rv);
        errors++;
        $finish;
      end
      n_prime = np_wide[RADIX-1:0];

      @(posedge clk);
      run_vector(i, exp_m);
      $display("*** vector %0d recombined in %0d cycles.", i, cycle_count);
    end
    $fclose(fin);

    $display("");
    $display("*** garner latency: min = %0d, max = %0d cycles.",
             min_cycles, max_cycles);
    if (min_cycles != max_cycles) begin
      $display("*** ERROR: garner latency is data dependent (spread = %0d cycles).",
               max_cycles - min_cycles);
      $display("***        p, q, qinv, m1 and m2 are all secret.");
      errors++;
    end

    if (errors == 0) begin
      $display("*** All %0d garner vectors passed.", VECTOR_NUM);
      $display("* TESTCASE PASSED");
    end
    else begin
      $display("*** %0d error(s).", errors);
      $display("* TESTCASE FAILED");
    end

    $display("*** tessera_rsa_crt_garner simulation done. ***");
    $finish;
  end

endmodule
