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
//
// rsa_mont_const_tb
//
// Check n_prime, R mod n and R^2 mod n against rsa_mont_const_vector_gen.py
// goldens, and measure LDMOD latency.
//
// Mirror tessera_rsa_params_pkg defines; the separate TB library cannot import it.

`ifndef RSA_KEY_SIZE_CONFIG
  `define RSA_KEY_SIZE_CONFIG 4096
`endif
`ifndef RSA_RADIX_CONFIG
  `define RSA_RADIX_CONFIG 64
`endif

module rsa_mont_const_tb;

  localparam int unsigned KEY_SIZE      = `RSA_KEY_SIZE_CONFIG;
  localparam int unsigned RADIX         = `RSA_RADIX_CONFIG;
  localparam int unsigned S_NUM         = ((KEY_SIZE + RADIX - 1) / RADIX) + 1;
  localparam int unsigned FULL_REG_SIZE = S_NUM * RADIX;
  localparam int unsigned NWORDS        = KEY_SIZE / RADIX;

  localparam int unsigned NUM_VECTORS   = 2;
  localparam string       VECTOR_FILE   =
      $sformatf("rsa_mont_const_vectors_%0d_key_%0d_word_%0d.hex", NUM_VECTORS, KEY_SIZE, RADIX);
  // KEY_SIZE/2-bit CRT primes use R_half = 2^(RADIX*S_NUM_H), not full-width R.
  localparam string       VECTOR_FILE_H =
      $sformatf("rsa_mont_const_vectors_half_%0d_key_%0d_word_%0d.hex", NUM_VECTORS, KEY_SIZE, RADIX);
  localparam int unsigned NWORDS_H        = NWORDS / 2;
  localparam int unsigned S_NUM_H         = NWORDS_H + 1;
  localparam int unsigned FULL_REG_SIZE_H = S_NUM_H * RADIX;

  // Latency bound for normalized moduli (bit KEY_SIZE-1 set): the first sweep
  // starts at msw*RADIX, with msw fixed at NWORDS-1 for legal inputs.
  // The R^2 chain uses CHAIN_MSB multiplies, at most CHAIN_MSB doublings
  // of NWORDS cycles each, and two handshake states per iteration.
  localparam int unsigned CHAIN_MSB      = $clog2(FULL_REG_SIZE + 1) - 1;
  localparam int unsigned MM_CYCLES      = 3*S_NUM + 8;
  localparam int unsigned SWEEP_DBLS     = FULL_REG_SIZE - (NWORDS-1)*RADIX + 2;
  localparam int unsigned EXPECTED_MAX   = SWEEP_DBLS*NWORDS
                                         + CHAIN_MSB*(MM_CYCLES + 2 + NWORDS)
                                         + 32;

  // Half mode still sweeps NWORDS: acc < p < 2^(KEY_SIZE/2) leaves upper words
  // zero.  A shorter target/chain and half-width multiplies (3*S_NUM_H+1)
  // reduce latency; MM_CYCLES_H includes service overhead.
  localparam int unsigned CHAIN_MSB_H     = $clog2(FULL_REG_SIZE_H + 1) - 1;
  localparam int unsigned MM_CYCLES_H     = 3*S_NUM_H + 8;
  localparam int unsigned SWEEP_DBLS_H    = FULL_REG_SIZE_H - (NWORDS_H-1)*RADIX + 2;
  localparam int unsigned EXPECTED_MAX_H  = SWEEP_DBLS_H*NWORDS
                                          + CHAIN_MSB_H*(MM_CYCLES_H + 2 + NWORDS)
                                          + 32;

  logic                    clk = 1'b0;
  logic                    rst_n;
  logic                    zeroize;
  logic                    start;
  logic [KEY_SIZE-1:0]     n;
  logic [RADIX-1:0]        n_prime;
  logic [KEY_SIZE-1:0]     r1;
  logic [KEY_SIZE-1:0]     r2;
  logic                    done;
  logic                    busy;

  logic                    mm_req;
  logic [KEY_SIZE-1:0]     mm_a;
  logic [KEY_SIZE-1:0]     mm_b;
  logic                    mm_done;
  logic [KEY_SIZE-1:0]     mm_result;
  logic                    mm_half;
  logic [7:0]              mm_geom;
  logic [5:0]              mm_sq_rep;
  logic                    half_tb;

  // Build lane 1; single-lane passes must still meet goldens and cycle bounds
  // with dual_tb low.
  logic                    dual_tb;
  logic [KEY_SIZE-1:0]     n1;
  logic [RADIX-1:0]        n_prime1;
  logic [KEY_SIZE-1:0]     r1_1;
  logic [KEY_SIZE-1:0]     r2_1;
  logic                    mm_dual;
  logic [KEY_SIZE-1:0]     mm_a1;
  logic [KEY_SIZE-1:0]     mm_b1;
  logic [KEY_SIZE-1:0]     mm_result1;

  int unsigned             errors = 0;
  int unsigned             cycle_count;

  always #5 clk = ~clk;

  tessera_rsa_mont_const #(
      .MODULUS_BIT_WIDTH (KEY_SIZE),
      .WORD_BIT_WIDTH    (RADIX),
      .FULL_REG_SIZE     (FULL_REG_SIZE),
      .DUAL_EN           (1'b1)
  ) dut (
      .clk               (clk),
      .rst_n             (rst_n),
      .zeroize           (zeroize),
      .start_in          (start),
      .n_in              (n),
      .half_i            (half_tb),
      .geom_i            (8'd0),
      .dual_i            (dual_tb),
      .n1_in             (n1),
      .n_prime_lsw_out   (n_prime),
      .r_pow_1_mod_n_out (r1),
      .r_pow_2_mod_n_out (r2),
      .n_prime1_lsw_out  (n_prime1),
      .r_pow_1_mod_n1_out(r1_1),
      .r_pow_2_mod_n1_out(r2_1),
      .mm_req_out        (mm_req),
      .mm_a_out          (mm_a),
      .mm_b_out          (mm_b),
      .mm_half_out       (mm_half),
      .mm_geom_out       (mm_geom),
      .mm_sq_rep_out     (mm_sq_rep),
      .mm_hold_out       (),
      .mm_done_in        (mm_done),
      .mm_result_in      (mm_result),
      .mm_dual_out       (mm_dual),
      .mm_a1_out         (mm_a1),
      .mm_b1_out         (mm_b1),
      .mm_result1_in     (mm_result1),
      .done_out          (done),
      .busy_out          (busy)
  );

  // Borrow the real tessera_rsa_modexp multiplier, as tessera_rsa_ctrl does, to test the
  // service handshake rather than a model.
  tessera_rsa_modexp #(
      .MODULUS_BIT_WIDTH  (KEY_SIZE),
      .EXPONENT_BIT_WIDTH (KEY_SIZE),
      .WORD_BIT_WIDTH     (RADIX),
      .DUAL_EN            (1'b1)
  ) mm_servicer (
      .clk                   (clk),
      .rst_n                 (rst_n),
      .start_in              (mm_req),
      .zeroize               (zeroize),
      .mul_mode_in           (1'b0),
      .mm_mode_in            (1'b1),
      .mm_half_in            (mm_half),
      .mm_geom_in            (mm_geom),
      .mm_sq_rep_in          (mm_sq_rep),
      // No ladder operation: mm_half_in selects the service multiply width.
      .half_in               (1'b0),
      .geom_in               (8'd0),
      .mul_b_in              (mm_b),
      .base_in               (mm_a),
      .exponent_in           ('0),
      .exponent_msb_index_in ('0),
      .exp_public_in         (1'b0),
      .n_in                  (n),
      .n_prime_lsw_in        (n_prime),
      .r_pow_1_mod_n_in      ('0),
      .r_pow_2_mod_n_in      ('0),
      // Lane 1 serves reducing multiplies; its ladder ports remain tied off.
      .dual_in               (mm_dual),
      .base1_in              (mm_a1),
      .exponent1_in          ('0),
      .n1_in                 (n1),
      .n_prime1_lsw_in       (n_prime1),
      .r_pow_1_mod_n1_in     ('0),
      .r_pow_2_mod_n1_in     ('0),
      .mul_b1_in             (mm_b1),
      .result_out            (mm_result),
      .result1_out           (mm_result1),
      .product_out           (),
      .done_out              (mm_done)
  );

  task automatic check_eq_wide(input string name, input logic [KEY_SIZE-1:0] got,
                               input logic [KEY_SIZE-1:0] exp);
    if (got !== exp) begin
      errors++;
      $display("ERROR: %s mismatch", name);
      $display("  expected %h", exp);
      $display("  got      %h", got);
    end
  endtask

  // Use identical stimulus for full- and half-width context derivation.
  task automatic run_vectors(input string  file,
                             input bit     half,
                             input int unsigned bound,
                             output logic [KEY_SIZE-1:0] last_n);
    int          fd;
    int          code;
    logic [KEY_SIZE-1:0] exp_n, exp_r1, exp_r2;
    logic [RADIX-1:0]    exp_np;
    int unsigned t0;

    fd = $fopen(file, "r");
    if (fd == 0) begin
      errors++;
      $display("ERROR: cannot open %s", file);
      return;
    end

    half_tb = half;
    for (int v = 0; v < NUM_VECTORS; v++) begin
      code = $fscanf(fd, "%h\n", exp_n);
      code = $fscanf(fd, "%h\n", exp_np);
      code = $fscanf(fd, "%h\n", exp_r1);
      code = $fscanf(fd, "%h\n", exp_r2);

      n = exp_n;
      @(posedge clk);
      t0    = 0;
      start = 1'b1;
      @(posedge clk);
      start = 1'b0;
      t0    = 1;
      while (!done) begin
        @(posedge clk);
        t0++;
      end
      cycle_count = t0;
      @(posedge clk);

      $display("%s vector %0d: LDMOD precompute took %0d cycles",
               half ? "HALF" : "FULL", v, cycle_count);
      if (n_prime !== exp_np) begin
        errors++;
        $display("ERROR: n_prime mismatch: expected %h got %h", exp_np, n_prime);
      end
      check_eq_wide("r_pow_1_mod_n", r1, exp_r1);
      check_eq_wide("r_pow_2_mod_n", r2, exp_r2);
      if (cycle_count > bound) begin
        errors++;
        $display("ERROR: %s ldmod took %0d cycles, above the %0d bound",
                 half ? "HALF" : "FULL", cycle_count, bound);
      end
    end
    $fclose(fd);
    last_n  = exp_n;
    half_tb = 1'b0;
  endtask

  // Pair adjacent half-width vectors and check both contexts from one run.
  // Normalized primes need no extra seeding doublings, so dual latency must
  // equal the single-lane half-width latency.
  task automatic run_dual_vectors(input string file, input int unsigned ref_cycles);
    int          fd;
    int          code;
    logic [KEY_SIZE-1:0] n_a, r1_a, r2_a;
    logic [RADIX-1:0]    np_a;
    logic [KEY_SIZE-1:0] n_b, r1_b, r2_b;
    logic [RADIX-1:0]    np_b;
    int unsigned t0;

    fd = $fopen(file, "r");
    if (fd == 0) begin
      errors++;
      $display("ERROR: cannot open %s", file);
      return;
    end

    // Seed a sliding pair of adjacent vectors with distinct lane contexts.
    code = $fscanf(fd, "%h\n", n_b);
    code = $fscanf(fd, "%h\n", np_b);
    code = $fscanf(fd, "%h\n", r1_b);
    code = $fscanf(fd, "%h\n", r2_b);

    for (int v = 1; v < NUM_VECTORS; v++) begin
      n_a = n_b;  np_a = np_b;  r1_a = r1_b;  r2_a = r2_b;
      code = $fscanf(fd, "%h\n", n_b);
      code = $fscanf(fd, "%h\n", np_b);
      code = $fscanf(fd, "%h\n", r1_b);
      code = $fscanf(fd, "%h\n", r2_b);

      n       = n_a;
      n1      = n_b;
      half_tb = 1'b1;
      dual_tb = 1'b1;
      @(posedge clk);
      t0    = 0;
      start = 1'b1;
      @(posedge clk);
      start = 1'b0;
      t0    = 1;
      while (!done) begin
        @(posedge clk);
        t0++;
      end
      cycle_count = t0;
      @(posedge clk);

      $display("DUAL vector %0d/%0d: LDMOD precompute took %0d cycles for BOTH contexts",
               v-1, v, cycle_count);

      if (n_prime !== np_a) begin
        errors++;
        $display("ERROR: dual lane 0 n_prime mismatch: expected %h got %h", np_a, n_prime);
      end
      if (n_prime1 !== np_b) begin
        errors++;
        $display("ERROR: dual lane 1 n_prime mismatch: expected %h got %h", np_b, n_prime1);
      end
      check_eq_wide("dual lane 0 r_pow_1_mod_n", r1,   r1_a);
      check_eq_wide("dual lane 0 r_pow_2_mod_n", r2,   r2_a);
      check_eq_wide("dual lane 1 r_pow_1_mod_n", r1_1, r1_b);
      check_eq_wide("dual lane 1 r_pow_2_mod_n", r2_1, r2_b);

      if (cycle_count != ref_cycles) begin
        errors++;
        $display("ERROR: dual ldmod took %0d cycles, single-lane half took %0d.",
                 cycle_count, ref_cycles);
        $display("       The second context is supposed to be free.");
      end
    end
    $fclose(fd);
    half_tb = 1'b0;
    dual_tb = 1'b0;
  endtask

  initial begin
    logic [KEY_SIZE-1:0] exp_n;
    int unsigned full_cycles, half_cycles;

    zeroize = 1'b0;
    start   = 1'b0;
    half_tb = 1'b0;
    dual_tb = 1'b0;
    n       = '0;
    n1      = '0;
    rst_n   = 1'b0;
    repeat (5) @(posedge clk);
    rst_n = 1'b1;
    repeat (2) @(posedge clk);

    run_vectors(VECTOR_FILE, 1'b0, EXPECTED_MAX, exp_n);
    full_cycles = cycle_count;

    // CRT branches require constants for half-width R, not full-width R.
    run_vectors(VECTOR_FILE_H, 1'b1, EXPECTED_MAX_H, exp_n);
    half_cycles = cycle_count;

    // Both CRT contexts from one derivation.
    run_dual_vectors(VECTOR_FILE_H, half_cycles);

    // Zeroize must abort an in-flight precompute and leave no residue.
    n = exp_n;
    @(posedge clk);
    start = 1'b1;
    @(posedge clk);
    start = 1'b0;
    repeat (100) @(posedge clk);
    zeroize = 1'b1;
    @(posedge clk);
    zeroize = 1'b0;
    @(posedge clk);
    if (busy !== 1'b0) begin
      errors++;
      $display("ERROR: zeroize did not return the precompute to idle");
    end
    if ((r1 !== '0) || (r2 !== '0) || (n_prime !== '0)) begin
      errors++;
      $display("ERROR: zeroize left residue in the Montgomery constants");
    end

    $display("---------------------------------------------");
    $display("RSA mont-const: KEY_SIZE=%0d RADIX=%0d S_NUM=%0d", KEY_SIZE, RADIX, S_NUM);
    $display("RSA_RESULT ldmod_cycles %0d (bound %0d)", full_cycles, EXPECTED_MAX);
    $display("RSA_RESULT ldmod_half_cycles %0d (bound %0d)", half_cycles, EXPECTED_MAX_H);
    $display("---------------------------------------------");

    if (errors == 0) $display("* TESTCASE PASSED");
    else             $display("* TESTCASE FAILED with %0d errors", errors);
    $finish;
  end

endmodule
