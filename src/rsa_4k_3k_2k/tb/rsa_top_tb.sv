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
// rsa_top_tb
//
// Exercise firmware-visible RSA flows through the AHB-Lite register file.
// Inspect write-only storage directly only for absent-CRT write gating.
//
// Cover identification, on-chip Montgomery constants, public/private/CRT
// results, constant-time private operations, and runtime key widths.
// Check context/command/modulus rejection, base reduction, plain multiply,
// and zeroization of operands, results and context.
//
// Mirror tessera_rsa_params_pkg defines; the separate TB library cannot import it.

`ifndef RSA_KEY_SIZE_CONFIG
  `define RSA_KEY_SIZE_CONFIG 4096
`endif
`ifndef RSA_RADIX_CONFIG
  `define RSA_RADIX_CONFIG 64
`endif
`ifndef RSA_CRT_ENABLE_CONFIG
  `define RSA_CRT_ENABLE_CONFIG 0
`endif

module rsa_top_tb;

  localparam int unsigned KEY_SIZE  = `RSA_KEY_SIZE_CONFIG;
  localparam int unsigned RADIX     = `RSA_RADIX_CONFIG;
  localparam int unsigned KEY_WORDS = KEY_SIZE / 32;
  localparam int unsigned EXP_SIZE  = KEY_SIZE + 64;
  localparam int unsigned EXP_WORDS = EXP_SIZE / 32;

  localparam int unsigned MOD_REGS = 128;
  localparam int unsigned A_REGS   = 128;
  localparam int unsigned E_REGS   = 4;
  localparam int unsigned D_REGS   = 132;
  localparam int unsigned RES_REGS = 128;
  localparam int unsigned B_REGS    = 128;
  localparam int unsigned PROD_REGS = 256;

  localparam logic [31:0] ADDR_NAME0   = 32'h0000_0000;
  localparam logic [31:0] ADDR_VERSION = 32'h0000_0008;
  localparam logic [31:0] ADDR_CTRL    = 32'h0000_0010;
  localparam logic [31:0] ADDR_STATUS  = 32'h0000_0018;
  localparam logic [31:0] ADDR_CONFIG  = 32'h0000_001C;
  localparam logic [31:0] ADDR_MODULUS = 32'h0000_0400;
  localparam logic [31:0] ADDR_A       = 32'h0000_0600;
  localparam logic [31:0] ADDR_E       = 32'h0000_0A00;
  localparam logic [31:0] ADDR_D       = 32'h0000_0C00;
  localparam logic [31:0] ADDR_B       = 32'h0000_0800;
  localparam logic [31:0] ADDR_RESULT  = 32'h0000_1000;
  localparam logic [31:0] ADDR_PRODUCT = 32'h0000_1200;
  localparam logic [31:0] ADDR_P       = 32'h0000_1600;
  localparam logic [31:0] ADDR_Q       = 32'h0000_1700;
  localparam logic [31:0] ADDR_QINV    = 32'h0000_1E00;

  // Every CRT aperture is 64 registers = half the 4096-bit modulus aperture.
  localparam int unsigned CRT_REGS   = 64;
  localparam int unsigned HALF_WORDS = KEY_WORDS / 2;
  localparam logic [31:0] ADDR_DP      = 32'h0000_1C00;
  localparam logic [31:0] ADDR_DQ      = 32'h0000_1D00;

  localparam logic [2:0]  CMD_LDMOD      = 3'b001;
  localparam logic [2:0]  CMD_MODEXP_PUB = 3'b010;
  localparam logic [2:0]  CMD_MODEXP_SEC = 3'b011;
  localparam logic [2:0]  CMD_MUL        = 3'b100;
  localparam logic [2:0]  CMD_GENPRIME   = 3'b101;  // reserved encoding
  localparam logic [2:0]  CMD_MODEXP_SEC_CRT = 3'b110;

  localparam int unsigned ERR_BAD_CMD     = 0;
  localparam int unsigned ERR_NO_CONTEXT  = 1;
  localparam int unsigned ERR_BAD_MOD     = 2;
  localparam int unsigned ERR_BAD_BASE    = 3;
  localparam int unsigned ERR_CRT_UNAVAIL = 4;
  localparam int unsigned ERR_MOD_RANGE   = 5;
  // Distinguish key rejection from post-flight Bellcore verification failure.
  localparam int unsigned ERR_CRT_FAIL    = 7;   // pre-flight: key refused
  localparam int unsigned ERR_CRT_VERIFY  = 10;  // post-flight: Bellcore failed
  // STATUS packs READY[0], VALID[1] and ERROR[17:2].
  localparam int unsigned ERR_BAD_KEYLEN  = 8;
  localparam int unsigned ERR_MOD_FIT     = 9;

  // Only 4096 builds have a supported half-width key (2048).  CTRL.KEY_LEN
  // encodes absolute lengths 2048/3072/4096; 1536 and 1024 are unsupported
  // (1024 is below the security floor) and map to ERR_BAD_KEYLEN.
  localparam bit          RT_ENABLE   = (KEY_SIZE == 4096);
  localparam int unsigned RT_KEY_SIZE = KEY_SIZE / 2;
  localparam logic [1:0]  RT_SHORTEN  = 2'(KEY_SIZE / 2048);

  // Three shortening steps always map to reserved CTRL.KEY_LEN=2'b11.
  localparam bit          RT_HAS_BAD     = 1'b1;
  localparam logic [1:0]  RT_BAD_SHORTEN = 2'd3;

  // Non-half runtime geometry: 3072 on a 4096 build, checked with ordinary
  // 3072-bit vectors rather than the half-width path.
  localparam bit          R3_ENABLE   = (KEY_SIZE == 4096);
  localparam int unsigned R3_KEY_SIZE = KEY_SIZE - 1024;
  localparam logic [1:0]  R3_SHORTEN  = 2'd1;

  // Use the same CRT build define as tessera_rsa_params_pkg.
  localparam bit CRT_ENABLE = (`RSA_CRT_ENABLE_CONFIG != 0);

  localparam int unsigned NUM_VECTORS = 2;

  // Usable NIST ACVP signature-primitive cases per modulus size (15 shipped,
  // 2 dropped as deliberately out-of-range message >= n).
  localparam int unsigned NUM_KAT_VECTORS = 13;

  // AHB
  logic        clk = 1'b0;
  logic        reset_n;
  logic        cptra_pwrgood;
  logic [31:0] haddr;
  logic [31:0] hwdata;
  logic        hsel;
  logic        hwrite;
  logic        hready;
  logic [1:0]  htrans;
  logic [2:0]  hsize;
  logic        hresp;
  logic        hreadyout;
  logic [31:0] hrdata;
  logic        busy;
  logic        error_intr;
  logic        notif_intr;
  logic        debug_unlock;

  int unsigned errors = 0;
  int unsigned cycle_counter;

  always #5 clk = ~clk;

  always_ff @(posedge clk or negedge reset_n) begin
    if (!reset_n) cycle_counter <= 0;
    else          cycle_counter <= cycle_counter + 1;
  end

  tessera_rsa_top dut (
      .clk           (clk),
      .reset_n       (reset_n),
      .cptra_pwrgood (cptra_pwrgood),
      .haddr_i       (haddr),
      .hwdata_i      (hwdata),
      .hsel_i        (hsel),
      .hwrite_i      (hwrite),
      .hready_i      (hready),
      .htrans_i      (htrans),
      .hsize_i       (hsize),
      .hresp_o       (hresp),
      .hreadyout_o   (hreadyout),
      .hrdata_o      (hrdata),
      .busy_o        (busy),
      .error_intr    (error_intr),
      .notif_intr    (notif_intr),
      .debugUnlock_or_scan_mode_switch (debug_unlock)
  );

  //--------------------------------------------------------------------------
  // Minimal AHB-Lite master: one non-sequential beat per access.
  //--------------------------------------------------------------------------
  task automatic ahb_write(input logic [31:0] addr, input logic [31:0] data);
    @(posedge clk);
    hsel   <= 1'b1;
    hwrite <= 1'b1;
    htrans <= 2'b10;
    hsize  <= 3'b010;
    haddr  <= addr;
    hready <= 1'b1;
    @(posedge clk);
    htrans <= 2'b00;
    hwdata <= data;
    @(posedge clk);
    hsel   <= 1'b0;
    hwrite <= 1'b0;
  endtask

  task automatic ahb_read(input logic [31:0] addr, output logic [31:0] data);
    @(posedge clk);
    hsel   <= 1'b1;
    hwrite <= 1'b0;
    htrans <= 2'b10;
    hsize  <= 3'b010;
    haddr  <= addr;
    hready <= 1'b1;
    @(posedge clk);
    htrans <= 2'b00;
    @(posedge clk);
    hsel   <= 1'b0;
    data = hrdata;
  endtask

  // Operands are big endian: register word 0 is the most significant, and a
  // key shorter than the 4096-bit aperture uses the high register indices.
  task automatic write_wide(input logic [31:0] base_addr, input int unsigned n_regs,
                            input int unsigned n_words, input logic [EXP_SIZE-1:0] value);
    for (int w = 0; w < n_words; w++) begin
      ahb_write(base_addr + 32'(4*(n_regs - n_words + w)), value[(n_words-1-w)*32 +: 32]);
    end
  endtask

  task automatic read_result(output logic [KEY_SIZE-1:0] value);
    logic [31:0] rd;
    value = '0;
    for (int w = 0; w < KEY_WORDS; w++) begin
      ahb_read(ADDR_RESULT + 32'(4*(RES_REGS - KEY_WORDS + w)), rd);
      value[(KEY_WORDS-1-w)*32 +: 32] = rd;
    end
  endtask

  // The 2*KEY_SIZE-bit product is right-aligned in the 256-register aperture.
  task automatic read_product(output logic [2*KEY_SIZE-1:0] value);
    logic [31:0] rd;
    value = '0;
    for (int w = 0; w < 2*KEY_WORDS; w++) begin
      ahb_read(ADDR_PRODUCT + 32'(4*(PROD_REGS - 2*KEY_WORDS + w)), rd);
      value[(2*KEY_WORDS-1-w)*32 +: 32] = rd;
    end
  endtask

  task automatic rand_wide(output logic [KEY_SIZE-1:0] value);
    for (int w = 0; w < KEY_WORDS; w++) value[w*32 +: 32] = $urandom();
  endtask

  task automatic wait_ready(output int unsigned cycles);
    logic [31:0] st;
    int unsigned t0;
    t0 = cycle_counter;
    forever begin
      ahb_read(ADDR_STATUS, st);
      if (st[0]) break;
    end
    cycles = cycle_counter - t0;
  endtask

  task automatic get_status(output logic [31:0] st);
    ahb_read(ADDR_STATUS, st);
  endtask

  task automatic expect_error(input string name, input int unsigned bit_idx);
    logic [31:0] st;
    int unsigned dummy;
    wait_ready(dummy);
    get_status(st);
    // Require only the expected error; extra bits can hide decode faults.
    if (st[17:2] !== (16'h1 << bit_idx)) begin
      errors++;
      $display("ERROR: %s reported ERROR = %h, expected only bit %0d (STATUS = %h)",
               name, st[17:2], bit_idx, st);
    end
    if (st[1] !== 1'b0) begin
      errors++;
      $display("ERROR: %s left STATUS.VALID set", name);
    end
  endtask

  //--------------------------------------------------------------------------
  // Golden vectors
  //--------------------------------------------------------------------------
  typedef struct {
    logic [KEY_SIZE-1:0] base;
    logic [KEY_SIZE-1:0] exponent;
    logic [KEY_SIZE-1:0] n;
    logic [KEY_SIZE-1:0] result;
  } vector_t;

  vector_t pub_vec [NUM_VECTORS];
  vector_t sec_vec [NUM_VECTORS];

  // NIST ACVP goldens provide a reference independent of the local model.
  vector_t kat_pub_vec [NUM_KAT_VECTORS];
  vector_t kat_sec_vec [NUM_KAT_VECTORS];

  // Reuse smaller-key vector files: whitespace-delimited hex tokens zero-extend
  // into KEY_SIZE-wide fields, matching the shortened datapath's convention.
  vector_t rt_pub_vec [NUM_VECTORS];
  vector_t rt_sec_vec [NUM_VECTORS];
  vector_t r3_pub_vec [NUM_VECTORS];
  vector_t r3_sec_vec [NUM_VECTORS];

  //--------------------------------------------------------------------------
  // CRT vectors: n d p q dp dq qinv base m, one line per key, full-width fields.
  // tb/rsa_crt_vector_gen.py derives golden m with non-CRT exponentiation.
  //--------------------------------------------------------------------------
  localparam int unsigned NUM_CRT_VECTORS = 2;

  typedef struct {
    logic [KEY_SIZE-1:0]   n;
    logic [KEY_SIZE-1:0]   d;
    logic [KEY_SIZE/2-1:0] p;
    logic [KEY_SIZE/2-1:0] q;
    logic [KEY_SIZE/2-1:0] dp;
    logic [KEY_SIZE/2-1:0] dq;
    logic [KEY_SIZE/2-1:0] qinv;
    logic [KEY_SIZE-1:0]   base;
    logic [KEY_SIZE-1:0]   m;
  } crt_vector_t;

  crt_vector_t crt_vec [NUM_CRT_VECTORS];
  // Separate CRT vectors for each supported runtime width.
  crt_vector_t r3_crt_vec [NUM_CRT_VECTORS];
  crt_vector_t rt_crt_vec [NUM_CRT_VECTORS];

  task automatic read_crt_vectors(input string fname, ref crt_vector_t crt_vec [NUM_CRT_VECTORS]);
    integer fin, rv, line_cnt, idx;
    logic [KEY_SIZE-1:0] val;
    fin = $fopen(fname, "r");
    if (fin == 0) begin
      errors++;
      $display("ERROR: cannot open %s", fname);
      return;
    end
    line_cnt = 0;
    idx      = 0;
    while ((!$feof(fin)) && (idx < NUM_CRT_VECTORS)) begin
      rv = $fscanf(fin, "%h\n", val);
      if (rv != 1) break;
      case (line_cnt % 9)
        0: crt_vec[idx].n    = val;
        1: crt_vec[idx].d    = val;
        2: crt_vec[idx].p    = val[KEY_SIZE/2-1:0];
        3: crt_vec[idx].q    = val[KEY_SIZE/2-1:0];
        4: crt_vec[idx].dp   = val[KEY_SIZE/2-1:0];
        5: crt_vec[idx].dq   = val[KEY_SIZE/2-1:0];
        6: crt_vec[idx].qinv = val[KEY_SIZE/2-1:0];
        7: crt_vec[idx].base = val;
        8: begin crt_vec[idx].m = val; idx++; end
        default: ;
      endcase
      line_cnt++;
    end
    $fclose(fin);
    if (idx != NUM_CRT_VECTORS) begin
      errors++;
      $display("ERROR: %s holds %0d CRT vectors, expected %0d",
               fname, idx, NUM_CRT_VECTORS);
    end
  endtask

  task automatic read_vectors(input string fname, ref vector_t dest[NUM_VECTORS]);
    integer fin, rv, line_cnt, idx;
    logic [KEY_SIZE-1:0] val;
    fin = $fopen(fname, "r");
    if (fin == 0) begin
      errors++;
      $display("ERROR: cannot open %s", fname);
      return;
    end
    line_cnt = 0;
    idx      = 0;
    while ((!$feof(fin)) && (idx < NUM_VECTORS)) begin
      rv = $fscanf(fin, "%h\n", val);
      if (rv != 1) break;
      case (line_cnt % 7)
        0: dest[idx].base     = val;
        1: dest[idx].exponent = val;
        2: dest[idx].n        = val;
        6: begin dest[idx].result = val; idx++; end
        default: ;
      endcase
      line_cnt++;
    end
    $fclose(fin);
  endtask

  task automatic read_kat_vectors(input string fname,
                                  ref vector_t dest[NUM_KAT_VECTORS]);
    integer fin, rv, line_cnt, idx;
    logic [KEY_SIZE-1:0] val;
    fin = $fopen(fname, "r");
    if (fin == 0) begin
      errors++;
      $display("ERROR: cannot open %s", fname);
      return;
    end
    line_cnt = 0;
    idx      = 0;
    while ((!$feof(fin)) && (idx < NUM_KAT_VECTORS)) begin
      rv = $fscanf(fin, "%h\n", val);
      if (rv != 1) break;
      case (line_cnt % 7)
        0: dest[idx].base     = val;
        1: dest[idx].exponent = val;
        2: dest[idx].n        = val;
        6: begin dest[idx].result = val; idx++; end
        default: ;
      endcase
      line_cnt++;
    end
    $fclose(fin);
    if (idx != NUM_KAT_VECTORS) begin
      errors++;
      $display("ERROR: %s holds %0d KAT vectors, expected %0d",
               fname, idx, NUM_KAT_VECTORS);
    end
  endtask

  //--------------------------------------------------------------------------
  // Command helpers
  //--------------------------------------------------------------------------
  // Translate TB opcodes to CTRL[3:0] (bit 3 selects CRT) or MUL[4].
  // CTRL also carries KEY_LEN[6:5] and ZEROIZE[7].

  logic [1:0] cfg_shorten = 2'b0;
  // Convert 1024-bit shortening steps to absolute CTRL.KEY_LEN encodings.
  // Unsupported lengths map to the reserved code for ERR_BAD_KEYLEN tests.
  function automatic logic [1:0] keylen_code(input logic [1:0] sh);
    int unsigned bits;
    bits = KEY_SIZE - 1024 * int'(sh);
    case (bits)
      2048:    keylen_code = 2'b00;
      3072:    keylen_code = 2'b01;
      4096:    keylen_code = 2'b10;
      default: keylen_code = 2'b11;
    endcase
  endfunction

  task automatic issue_cmd(input logic [2:0] cmd);
    logic [31:0] ctrl_word;
    ctrl_word = 32'h0;
    unique case (cmd)
      CMD_MUL:            ctrl_word[4]   = 1'b1;
      CMD_MODEXP_SEC_CRT: ctrl_word[3:0] = 4'b1011;
      // Pass other opcodes, including reserved test values, without CRT.
      default:            ctrl_word[3:0] = {1'b0, cmd};
    endcase
    ctrl_word[6:5] = keylen_code(cfg_shorten);
    ahb_write(ADDR_CTRL, ctrl_word);
  endtask

  // CONFIG exposes read-only CRT_SUPPORTED; command width is in CTRL.KEY_LEN.
  // Hardware derives the public ladder length from RSA_E.


  // Set cfg_shorten before LDMOD: it binds the width-dependent context.
  task automatic do_ldmod(input logic [KEY_SIZE-1:0] n, output int unsigned cycles);
    write_wide(ADDR_MODULUS, MOD_REGS, KEY_WORDS, EXP_SIZE'(n));
    issue_cmd(CMD_LDMOD);
    wait_ready(cycles);
  endtask

  task automatic do_modexp(input logic [2:0] cmd, input logic [KEY_SIZE-1:0] base,
                           input logic [KEY_SIZE-1:0] exp,
                           output logic [KEY_SIZE-1:0] res, output int unsigned cycles);
    write_wide(ADDR_A, A_REGS, KEY_WORDS, EXP_SIZE'(base));
    if (cmd == CMD_MODEXP_PUB) write_wide(ADDR_E, E_REGS, E_REGS, EXP_SIZE'(exp));
    else                       write_wide(ADDR_D, D_REGS, EXP_WORDS, EXP_SIZE'(exp));
    issue_cmd(cmd);
    wait_ready(cycles);
    read_result(res);
  endtask

  // MUL needs no LDMOD or modulus-relative range check.
  task automatic do_mul(input logic [KEY_SIZE-1:0] a, input logic [KEY_SIZE-1:0] b,
                        output logic [2*KEY_SIZE-1:0] prod, output int unsigned cycles);
    write_wide(ADDR_A, A_REGS, KEY_WORDS, EXP_SIZE'(a));
    write_wide(ADDR_B, B_REGS, KEY_WORDS, EXP_SIZE'(b));
    issue_cmd(CMD_MUL);
    wait_ready(cycles);
    read_product(prod);
  endtask

  //--------------------------------------------------------------------------
  // CRT key material.
  //
  // Load the write-only CRT apertures before LDMOD builds the p/q contexts
  // and arms CRT.
  //--------------------------------------------------------------------------
  task automatic load_crt_key(input crt_vector_t v);
    write_wide(ADDR_P,    CRT_REGS, HALF_WORDS, EXP_SIZE'(v.p));
    write_wide(ADDR_Q,    CRT_REGS, HALF_WORDS, EXP_SIZE'(v.q));
    write_wide(ADDR_DP,   CRT_REGS, HALF_WORDS, EXP_SIZE'(v.dp));
    write_wide(ADDR_DQ,   CRT_REGS, HALF_WORDS, EXP_SIZE'(v.dq));
    write_wide(ADDR_QINV, CRT_REGS, HALF_WORDS, EXP_SIZE'(v.qinv));
  endtask

  task automatic check_mul(input string name, input logic [KEY_SIZE-1:0] a,
                           input logic [KEY_SIZE-1:0] b,
                           input logic [2*KEY_SIZE-1:0] got);
    logic [2*KEY_SIZE-1:0] wa, wb, expected;
    wa       = {{KEY_SIZE{1'b0}}, a};
    wb       = {{KEY_SIZE{1'b0}}, b};
    expected = wa * wb;
    if (got !== expected) begin
      errors++;
      $display("ERROR: %s mismatch", name);
      $display("  a        %h", a);
      $display("  b        %h", b);
      $display("  expected %h", expected);
      $display("  got      %h", got);
    end
  endtask

  task automatic check_wide(input string name, input logic [KEY_SIZE-1:0] got,
                            input logic [KEY_SIZE-1:0] exp);
    if (got !== exp) begin
      errors++;
      $display("ERROR: %s mismatch", name);
      $display("  expected %h", exp);
      $display("  got      %h", got);
    end
  endtask

  //--------------------------------------------------------------------------
  // Main
  //--------------------------------------------------------------------------
  initial begin : main
    logic [31:0]         rd, st;
    logic [KEY_SIZE-1:0] res;
    logic [KEY_SIZE-1:0] even_n;
    logic [KEY_SIZE-1:0] big_n;
    logic [KEY_SIZE-1:0] mul_a, mul_b;
    logic [2*KEY_SIZE-1:0] prod;
    int unsigned         ldmod_cycles;
    int unsigned         pub_cycles, sec_cycles, sec_cycles2, sec_short_cycles;
    int unsigned         kat_sec_cycles;
    int unsigned         mul_cycles, mul_cycles2;
    int unsigned         dummy;
    int unsigned         crt_ldmod_cycles, crt_cycles, crt_cycles2;
    int unsigned         r3_crt_ldmod_cycles, r3_crt_cycles, r3_crt_cycles2;
    int unsigned         rt_crt_ldmod_cycles, rt_crt_cycles, rt_crt_cycles2;
    logic [KEY_SIZE-1:0] crt_res;
    int unsigned         rt_ldmod_cycles, rt_pub_cycles, rt_sec_cycles, rt_sec_cycles2;
    int unsigned         rt_mul_cycles;
    int unsigned         r3_ldmod_cycles, r3_pub_cycles, r3_sec_cycles, r3_sec_cycles2;
    int unsigned         r3_mul_cycles;
    logic [KEY_SIZE-1:0] long_n;

    hsel = 0; hwrite = 0; htrans = 0; hsize = 0; haddr = 0; hwdata = 0; hready = 1;
    debug_unlock = 0; cptra_pwrgood = 0; reset_n = 0;
    repeat (5) @(posedge clk);
    cptra_pwrgood = 1;
    repeat (2) @(posedge clk);
    reset_n = 1;
    repeat (5) @(posedge clk);

    $display("   -= Testbench for tessera_rsa_top started =-");
    $display("*** CONFIG: KEY_SIZE = %0d, RADIX = %0d", KEY_SIZE, RADIX);

    read_vectors($sformatf("rsa_modexp_pub_vectors_%0d_key_%0d_word_%0d.hex",
                           NUM_VECTORS, KEY_SIZE, RADIX), pub_vec);
    read_vectors($sformatf("rsa_modexp_sec_vectors_%0d_key_%0d_word_%0d.hex",
                           NUM_VECTORS, KEY_SIZE, RADIX), sec_vec);
    read_kat_vectors($sformatf("rsa_modexp_kat_pub_vectors_%0d_key_%0d_word_%0d.hex",
                               NUM_KAT_VECTORS, KEY_SIZE, RADIX), kat_pub_vec);
    read_kat_vectors($sformatf("rsa_modexp_kat_sec_vectors_%0d_key_%0d_word_%0d.hex",
                               NUM_KAT_VECTORS, KEY_SIZE, RADIX), kat_sec_vec);
    if (CRT_ENABLE) begin
      read_crt_vectors($sformatf("rsa_crt_vectors_%0d_key_%0d_word_%0d.hex",
                                 NUM_CRT_VECTORS, KEY_SIZE, RADIX), crt_vec);
    end
    if (RT_ENABLE) begin
      read_vectors($sformatf("rsa_modexp_pub_vectors_%0d_key_%0d_word_%0d.hex",
                             NUM_VECTORS, RT_KEY_SIZE, RADIX), rt_pub_vec);
      read_vectors($sformatf("rsa_modexp_sec_vectors_%0d_key_%0d_word_%0d.hex",
                             NUM_VECTORS, RT_KEY_SIZE, RADIX), rt_sec_vec);
      if (CRT_ENABLE) begin
        read_crt_vectors($sformatf("rsa_crt_vectors_%0d_key_%0d_word_%0d.hex",
                                   NUM_CRT_VECTORS, RT_KEY_SIZE, RADIX),
                         rt_crt_vec);
      end
    end
    if (R3_ENABLE) begin
      read_vectors($sformatf("rsa_modexp_pub_vectors_%0d_key_%0d_word_%0d.hex",
                             NUM_VECTORS, R3_KEY_SIZE, RADIX), r3_pub_vec);
      read_vectors($sformatf("rsa_modexp_sec_vectors_%0d_key_%0d_word_%0d.hex",
                             NUM_VECTORS, R3_KEY_SIZE, RADIX), r3_sec_vec);
      if (CRT_ENABLE) begin
        read_crt_vectors($sformatf("rsa_crt_vectors_%0d_key_%0d_word_%0d.hex",
                                   NUM_CRT_VECTORS, R3_KEY_SIZE, RADIX),
                         r3_crt_vec);
      end
    end

    //----------------------------------------------------------------------
    // Identification
    //----------------------------------------------------------------------
    ahb_read(ADDR_NAME0, rd);
    if (rd !== 32'h0061_7372) begin   // "rsa"
      errors++;
      $display("ERROR: RSA_NAME[0] reads %h", rd);
    end
    ahb_read(ADDR_VERSION, rd);
    if (rd !== 32'h3030_312e) begin   // "1.00"
      errors++;
      $display("ERROR: RSA_VERSION[0] reads %h", rd);
    end
    ahb_read(ADDR_CONFIG, rd);

    //----------------------------------------------------------------------
    // CRT configuration
    //
    // Read-only CRT_SUPPORTED must match the synthesized build parameter.
    //----------------------------------------------------------------------
    // CONFIG contains only CRT_SUPPORTED at bit 0.
    if (rd[0] !== CRT_ENABLE) begin
      errors++;
      $display("ERROR: CONFIG.CRT_SUPPORTED reads %b, expected %b", rd[0], CRT_ENABLE);
    end
    if (rd[31:1] !== 31'h0) begin
      errors++;
      $display("ERROR: CONFIG has no fields above bit 0 and they must read 0 (CONFIG = %h)", rd);
    end

    // An absent CRT datapath must not latch key material.  P is write-only,
    // so inspect its storage rather than reading it through the bus.
    if (!CRT_ENABLE) begin
      write_wide(ADDR_P, CRT_REGS, HALF_WORDS, EXP_SIZE'(1));
      if (dut.rsa_reg1.field_storage.RSA_P[CRT_REGS-1].P.value !== 32'h0) begin
        errors++;
        $display("ERROR: RSA_P latched a write on an instance without CRT (%h)",
                 dut.rsa_reg1.field_storage.RSA_P[CRT_REGS-1].P.value);
      end
    end

    // Distinguish an unavailable CRT datapath from an invalid command encoding.
    if (!CRT_ENABLE) begin
      issue_cmd(CMD_MODEXP_SEC_CRT);
      expect_error("MODEXP_SEC_CRT with CRT compiled out", ERR_CRT_UNAVAIL);
    end

    //----------------------------------------------------------------------
    // A MODEXP with no modulus context must be rejected
    //----------------------------------------------------------------------
    issue_cmd(CMD_MODEXP_PUB);
    expect_error("MODEXP before LDMOD", ERR_NO_CONTEXT);

    //----------------------------------------------------------------------
    // An unsupported command encoding must be rejected
    //----------------------------------------------------------------------
    issue_cmd(CMD_GENPRIME);
    expect_error("unimplemented GENPRIME", ERR_BAD_CMD);

    //----------------------------------------------------------------------
    // MUL before LDMOD verifies independence from Montgomery context.
    //----------------------------------------------------------------------
    mul_a = '0; mul_b = '0;
    mul_a[7:0] = 8'hFF; mul_b[7:0] = 8'h03;
    do_mul(mul_a, mul_b, prod, mul_cycles);
    check_mul("MUL small operands", mul_a, mul_b, prod);

    // All-ones operands stress the full product width and low/high word split.
    mul_a = {KEY_SIZE{1'b1}};
    mul_b = {KEY_SIZE{1'b1}};
    do_mul(mul_a, mul_b, prod, mul_cycles);
    check_mul("MUL all ones", mul_a, mul_b, prod);

    rand_wide(mul_a);
    rand_wide(mul_b);
    do_mul(mul_a, mul_b, prod, mul_cycles);
    check_mul("MUL random operands", mul_a, mul_b, prod);
    $display("RSA_RESULT mul_cycles %0d", mul_cycles);

    // MUL must leave RSA_RESULT zero so VALID cannot expose a stale result.
    read_result(res);
    if (res !== '0) begin
      errors++;
      $display("ERROR: MUL left a stale RSA_RESULT: %h", res);
    end

    //----------------------------------------------------------------------
    // An even modulus must be rejected
    //----------------------------------------------------------------------
    even_n      = sec_vec[0].n;
    even_n[0]   = 1'b0;
    write_wide(ADDR_MODULUS, MOD_REGS, KEY_WORDS, EXP_SIZE'(even_n));
    issue_cmd(CMD_LDMOD);
    expect_error("even modulus", ERR_BAD_MOD);
    // Failed LDMOD must not leave a usable context.
    issue_cmd(CMD_MODEXP_PUB);
    expect_error("MODEXP after failed LDMOD", ERR_NO_CONTEXT);

    //----------------------------------------------------------------------
    // A modulus whose top RADIX bits are all ones must be rejected.
    //
    // Lazy reduction gives u < n*(1 + 2^-RADIX).  The KEY_SIZE-wide result port
    // requires u < 2^KEY_SIZE; enforce n < 2^KEY_SIZE - 2^(KEY_SIZE-RADIX)
    // to prevent truncation.  Directed coverage is needed because random
    // moduli hit this caller-controlled region with probability only ~2^-RADIX.
    //----------------------------------------------------------------------
    big_n = sec_vec[0].n;
    big_n[KEY_SIZE-1 -: RADIX] = {RADIX{1'b1}};   // force the top word to all ones
    big_n[0] = 1'b1;                              // keep it odd so ERR_BAD_MOD cannot fire
    write_wide(ADDR_MODULUS, MOD_REGS, KEY_WORDS, EXP_SIZE'(big_n));
    issue_cmd(CMD_LDMOD);
    expect_error("modulus above the lazy-reduction bound", ERR_MOD_RANGE);
    issue_cmd(CMD_MODEXP_PUB);
    expect_error("MODEXP after out-of-range LDMOD", ERR_NO_CONTEXT);

    //----------------------------------------------------------------------
    // Restore a valid modulus and base before public-key checks.
    //----------------------------------------------------------------------
    write_wide(ADDR_MODULUS, MOD_REGS, KEY_WORDS, EXP_SIZE'(pub_vec[0].n));
    issue_cmd(CMD_LDMOD);
    wait_ready(dummy);
    write_wide(ADDR_A, A_REGS, KEY_WORDS, EXP_SIZE'(pub_vec[0].base));

    //----------------------------------------------------------------------
    // Public-key exponentiation.  The Montgomery constants are derived on
    // chip by LDMOD, so the vectors' n_prime / R / R^2 fields are unused.
    //----------------------------------------------------------------------
    do_ldmod(pub_vec[0].n, ldmod_cycles);
    get_status(st);
    if (st[1] !== 1'b1) begin
      errors++;
      $display("ERROR: LDMOD did not set STATUS.VALID (STATUS = %h)", st);
    end
    $display("RSA_RESULT ldmod_cycles %0d", ldmod_cycles);

    do_modexp(CMD_MODEXP_PUB, pub_vec[0].base, pub_vec[0].exponent, res, pub_cycles);
    check_wide("MODEXP_PUB result", res, pub_vec[0].result);
    $display("RSA_RESULT modexp_pub_cycles %0d", pub_cycles);

    //----------------------------------------------------------------------
    // MUL must not disturb the modulus context established by LDMOD, and it
    // must take the same time regardless of the operand values.
    //----------------------------------------------------------------------
    rand_wide(mul_a);
    rand_wide(mul_b);
    do_mul(mul_a, mul_b, prod, mul_cycles2);
    check_mul("MUL after LDMOD", mul_a, mul_b, prod);
    if (mul_cycles2 !== mul_cycles) begin
      errors++;
      $display("ERROR: MUL latency is operand dependent: %0d vs %0d cycles",
               mul_cycles, mul_cycles2);
    end

    do_modexp(CMD_MODEXP_PUB, pub_vec[0].base, pub_vec[0].exponent, res, dummy);
    check_wide("MODEXP_PUB result after MUL", res, pub_vec[0].result);

    // MODEXP must also clear the previous plain product.
    read_product(prod);
    if (prod !== '0) begin
      errors++;
      $display("ERROR: MODEXP left a stale RSA_PRODUCT: %h", prod);
    end

    //----------------------------------------------------------------------
    // Bases in [n, 2^KEY_LEN) are reduced: n+1 must produce 1^e = 1.
    //----------------------------------------------------------------------
    do_modexp(CMD_MODEXP_PUB, pub_vec[0].n + 1'b1, pub_vec[0].exponent,
              res, dummy);
    check_wide("base n+1 reduces to 1", res, EXP_SIZE'(1));

    // The equality boundary n must reduce to zero.
    do_modexp(CMD_MODEXP_PUB, pub_vec[0].n, pub_vec[0].exponent, res, dummy);
    check_wide("base n reduces to 0", res, EXP_SIZE'(0));

    //----------------------------------------------------------------------
    // Private-key exponentiation with its own modulus context.
    //----------------------------------------------------------------------
    do_ldmod(sec_vec[0].n, ldmod_cycles);
    do_modexp(CMD_MODEXP_SEC, sec_vec[0].base, sec_vec[0].exponent, res, sec_cycles);
    check_wide("MODEXP_SEC result", res, sec_vec[0].result);
    $display("RSA_RESULT modexp_sec_cycles %0d", sec_cycles);

    // A different secret exponent must take exactly the same time.
    do_ldmod(sec_vec[1].n, ldmod_cycles);
    do_modexp(CMD_MODEXP_SEC, sec_vec[1].base, sec_vec[1].exponent, res, sec_cycles2);
    check_wide("MODEXP_SEC result (vector 1)", res, sec_vec[1].result);
    if (sec_cycles2 !== sec_cycles) begin
      errors++;
      $display("ERROR: private ladder is not constant time: %0d vs %0d cycles",
               sec_cycles, sec_cycles2);
    end

    //----------------------------------------------------------------------
    // Repeating the same private operation must preserve latency and result.
    //----------------------------------------------------------------------
    do_ldmod(sec_vec[1].n, ldmod_cycles);
    do_modexp(CMD_MODEXP_SEC, sec_vec[1].base, sec_vec[1].exponent, res, sec_short_cycles);
    if (sec_short_cycles !== sec_cycles2) begin
      errors++;
      $display("ERROR: CONFIG.EXP_LEN shortened the private ladder: %0d vs %0d cycles",
               sec_cycles2, sec_short_cycles);
    end else begin
      $display("CONFIG.EXP_LEN has no effect on MODEXP_SEC: %0d cycles either way",
               sec_short_cycles);
    end
    check_wide("MODEXP_SEC result with EXP_LEN forced low", res, sec_vec[1].result);

    //----------------------------------------------------------------------
    // NIST ACVP known-answer tests through the register interface.
    //
    // Unlike the modexp unit TB, derive constants on chip with LDMOD for each
    // NIST key.  Run all 13 public cases and one costly private case; the unit
    // TB provides additional private-key coverage.
    //----------------------------------------------------------------------
    for (int k = 0; k < NUM_KAT_VECTORS; k++) begin
      do_ldmod(kat_pub_vec[k].n, ldmod_cycles);
      do_modexp(CMD_MODEXP_PUB, kat_pub_vec[k].base, kat_pub_vec[k].exponent, res, dummy);
      check_wide($sformatf("NIST ACVP MODEXP_PUB vector %0d", k),
                 res, kat_pub_vec[k].result);
    end
    $display("NIST ACVP: %0d public known-answer vectors passed", NUM_KAT_VECTORS);

    do_ldmod(kat_sec_vec[0].n, ldmod_cycles);
    do_modexp(CMD_MODEXP_SEC, kat_sec_vec[0].base, kat_sec_vec[0].exponent, res, kat_sec_cycles);
    check_wide("NIST ACVP MODEXP_SEC vector 0", res, kat_sec_vec[0].result);
    // NIST and local private keys must have equal latency.
    if (kat_sec_cycles !== sec_cycles) begin
      errors++;
      $display("ERROR: NIST ACVP MODEXP_SEC took %0d cycles, local vectors took %0d",
               kat_sec_cycles, sec_cycles);
    end else begin
      $display("NIST ACVP: private known-answer vector passed in %0d cycles",
               kat_sec_cycles);
    end

    //----------------------------------------------------------------------
    // MODEXP_SEC_CRT
    //
    // Exercise built-in CRT; ERR_CRT_UNAVAIL is checked above when absent.
    //----------------------------------------------------------------------
    if (CRT_ENABLE) begin
      for (int v = 0; v < NUM_CRT_VECTORS; v++) begin
        // LDMOD requires p/q loaded before building their contexts.
        load_crt_key(crt_vec[v]);
        do_ldmod(crt_vec[v].n, crt_ldmod_cycles);
        if (v == 0) $display("RSA_RESULT crt_ldmod_cycles %0d", crt_ldmod_cycles);

        // Bellcore verification uses e = 65537.
        write_wide(ADDR_A, A_REGS, KEY_WORDS, EXP_SIZE'(crt_vec[v].base));
        write_wide(ADDR_E, E_REGS, E_REGS, EXP_SIZE'(32'h0001_0001));
        issue_cmd(CMD_MODEXP_SEC_CRT);
        wait_ready(crt_cycles);
        get_status(st);
        if (st[1] !== 1'b1) begin
          errors++;
          $display("ERROR: MODEXP_SEC_CRT vector %0d did not set VALID (STATUS = %h)",
                   v, st);
        end
        if (st[17:2] !== 16'h0000) begin
          errors++;
          $display("ERROR: MODEXP_SEC_CRT vector %0d raised ERROR = %h", v, st[17:2]);
        end
        read_result(crt_res);
        check_wide($sformatf("MODEXP_SEC_CRT vector %0d", v), crt_res, crt_vec[v].m);

        if (v == 0) begin
          crt_cycles2 = crt_cycles;
          $display("RSA_RESULT modexp_sec_crt_cycles %0d", crt_cycles);
        end else if (crt_cycles !== crt_cycles2) begin
          // Latency must not depend on the private key or dp/dq values.
          errors++;
          $display("ERROR: MODEXP_SEC_CRT is not constant time: %0d vs %0d cycles",
                   crt_cycles, crt_cycles2);
        end
      end

      // Cross-check the same key through non-CRT exponentiation.  Reload
      // vector 0's context: the loop left the last vector's modulus active.
      load_crt_key(crt_vec[0]);
      do_ldmod(crt_vec[0].n, dummy);
      do_modexp(CMD_MODEXP_SEC, crt_vec[0].base, crt_vec[0].d,
                res, dummy);
      check_wide("MODEXP_SEC agrees with MODEXP_SEC_CRT", res, crt_vec[0].m);
      $display("CRT speedup over MODEXP_SEC: %0d -> %0d cycles (%0d/100 x)",
               dummy, crt_cycles2, (dummy * 100) / crt_cycles2);

      // Flip dp's low bit without making it structurally invalid.  Bellcore
      // verification must withhold the faulted result to prevent factor leakage.
      write_wide(ADDR_DP, CRT_REGS, HALF_WORDS,
                 EXP_SIZE'(crt_vec[0].dp ^ {{(KEY_SIZE/2-1){1'b0}}, 1'b1}));
      write_wide(ADDR_A, A_REGS, KEY_WORDS, EXP_SIZE'(crt_vec[0].base));
      // Retain RSA_E; hardware derives the verification exponent length.
      issue_cmd(CMD_MODEXP_SEC_CRT);
      wait_ready(dummy);
      get_status(st);
      if (st[1] !== 1'b0) begin
        errors++;
        $display("ERROR: faulted CRT branch still set STATUS.VALID (%h)", st);
      end
      // A withheld post-flight result reports ERR_CRT_VERIFY, not key rejection.
      if (st[2 + ERR_CRT_VERIFY] !== 1'b1) begin
        errors++;
        $display("ERROR: faulted CRT branch did not report ERROR bit %0d (STATUS = %h)",
                 ERR_CRT_VERIFY, st);
      end
      if (st[2 + ERR_CRT_FAIL] !== 1'b0) begin
        errors++;
        $display("ERROR: faulted CRT branch also set the pre-flight bit %0d (STATUS = %h)",
                 ERR_CRT_FAIL, st);
      end
      read_result(res);
      if (res !== '0) begin
        errors++;
        $display("ERROR: faulted CRT branch leaked a result (%h)", res);
      end
      $display("CRT Bellcore fault check exercised");

      // Restore a valid key and context before the next rejection check.
      load_crt_key(crt_vec[0]);
      do_ldmod(crt_vec[0].n, dummy);

      // An even p must fail pre-flight, before Bellcore verification.
      write_wide(ADDR_P, CRT_REGS, HALF_WORDS,
                 EXP_SIZE'(crt_vec[0].p & ~{{(KEY_SIZE/2-1){1'b0}}, 1'b1}));
      issue_cmd(CMD_MODEXP_SEC_CRT);
      expect_error("MODEXP_SEC_CRT with even p", ERR_CRT_FAIL);
      load_crt_key(crt_vec[0]);
    end

    //----------------------------------------------------------------------
    // Runtime key length (CTRL.KEY_LEN)
    //
    // A half-width key must run faster than a native-width key.  Use the
    // smaller native build's ordinary vectors as independent goldens.
    //----------------------------------------------------------------------
    if (RT_ENABLE) begin
      //--------------------------------------------------------------------
      // Rejections first, while the context is still the full-width one.
      //--------------------------------------------------------------------
      // Unsupported shortening maps to the reserved key-length encoding.
      if (RT_HAS_BAD) begin
        cfg_shorten = RT_BAD_SHORTEN;
        issue_cmd(CMD_LDMOD);
        expect_error("LDMOD with an unsupported CTRL.KEY_LEN", ERR_BAD_KEYLEN);

        // MUL must reject the same unsupported length.
        cfg_shorten = RT_BAD_SHORTEN;
        issue_cmd(CMD_MUL);
        expect_error("MUL with an unsupported CTRL.KEY_LEN", ERR_BAD_KEYLEN);
      end

      // Reject oversized MUL operands rather than silently truncating them.
      mul_a = '0;
      mul_b = '0;
      mul_a[KEY_SIZE-1] = 1'b1;
      mul_b[3:0]        = 4'hF;
      write_wide(ADDR_A, A_REGS, KEY_WORDS, EXP_SIZE'(mul_a));
      write_wide(ADDR_B, B_REGS, KEY_WORDS, EXP_SIZE'(mul_b));
      cfg_shorten = RT_SHORTEN;
      issue_cmd(CMD_MUL);
      expect_error("MUL with an operand wider than CTRL.KEY_LEN", ERR_BAD_BASE);
      // Leave cfg_shorten at RT_SHORTEN: the CRT rejection below depends on it.

      if (CRT_ENABLE) begin
        // CRT context width tags must match the command.  Build at native
        // width, then request shortened CRT to check rejection.
        cfg_shorten = 2'd0;
        load_crt_key(crt_vec[0]);
        do_ldmod(crt_vec[0].n, dummy);
        cfg_shorten = RT_SHORTEN;
        issue_cmd(CMD_MODEXP_SEC_CRT);
        expect_error("MODEXP_SEC_CRT against a native-width CRT context",
                     ERR_BAD_KEYLEN);
      end
      cfg_shorten = RT_SHORTEN;

      // A bit above the selected width must cause rejection, not truncation.
      long_n = rt_pub_vec[0].n;
      long_n[KEY_SIZE-1] = 1'b1;
      cfg_shorten = RT_SHORTEN;
      write_wide(ADDR_MODULUS, MOD_REGS, KEY_WORDS, EXP_SIZE'(long_n));
      issue_cmd(CMD_LDMOD);
      expect_error("shortened LDMOD with a bit set above the key length",
                   ERR_MOD_FIT);

      // Require a normalized modulus at the declared public key width.
      long_n = rt_pub_vec[0].n;
      long_n[RT_KEY_SIZE-1] = 1'b0;
      write_wide(ADDR_MODULUS, MOD_REGS, KEY_WORDS, EXP_SIZE'(long_n));
      issue_cmd(CMD_LDMOD);
      expect_error("shortened LDMOD with the top key bit clear", ERR_MOD_FIT);

      //--------------------------------------------------------------------
      // Reject width-mismatched contexts: Montgomery R and R^2 depend on width.
      //--------------------------------------------------------------------
      cfg_shorten = 2'd0;
      do_ldmod(pub_vec[0].n, dummy);
      cfg_shorten = RT_SHORTEN;
      issue_cmd(CMD_MODEXP_SEC);
      expect_error("shortened MODEXP against a full-width context",
                   ERR_BAD_KEYLEN);

      // Reject the reverse width mismatch too.
      cfg_shorten = RT_SHORTEN;
      do_ldmod(rt_pub_vec[0].n, rt_ldmod_cycles);
      cfg_shorten = 2'd0;
      issue_cmd(CMD_MODEXP_SEC);
      expect_error("full-width MODEXP against a shortened context",
                   ERR_BAD_KEYLEN);

      //--------------------------------------------------------------------
      // Valid shortened-width operations.
      //--------------------------------------------------------------------
      cfg_shorten = RT_SHORTEN;
      do_ldmod(rt_pub_vec[0].n, rt_ldmod_cycles);
      $display("RSA_RESULT rt_ldmod_cycles %0d", rt_ldmod_cycles);

      for (int v = 0; v < NUM_VECTORS; v++) begin
        do_ldmod(rt_pub_vec[v].n, dummy);
        do_modexp(CMD_MODEXP_PUB, rt_pub_vec[v].base, rt_pub_vec[v].exponent, res, rt_pub_cycles);
        check_wide($sformatf("runtime-%0d MODEXP_PUB vector %0d", RT_KEY_SIZE, v),
                   res, rt_pub_vec[v].result);
      end
      $display("RSA_RESULT rt_modexp_pub_cycles %0d", rt_pub_cycles);

      do_ldmod(rt_sec_vec[0].n, dummy);
      do_modexp(CMD_MODEXP_SEC, rt_sec_vec[0].base, rt_sec_vec[0].exponent, res, rt_sec_cycles);
      check_wide($sformatf("runtime-%0d MODEXP_SEC vector 0", RT_KEY_SIZE),
                 res, rt_sec_vec[0].result);
      $display("RSA_RESULT rt_modexp_sec_cycles %0d", rt_sec_cycles);

      //--------------------------------------------------------------------
      // Latency may vary with public key width, never with secret exponents
      // at the same width.
      //--------------------------------------------------------------------
      do_ldmod(rt_sec_vec[1].n, dummy);
      do_modexp(CMD_MODEXP_SEC, rt_sec_vec[1].base, rt_sec_vec[1].exponent, res, rt_sec_cycles2);
      check_wide($sformatf("runtime-%0d MODEXP_SEC vector 1", RT_KEY_SIZE),
                 res, rt_sec_vec[1].result);
      if (rt_sec_cycles2 !== rt_sec_cycles) begin
        errors++;
        $display("ERROR: shortened MODEXP_SEC is not constant time: %0d vs %0d cycles",
                 rt_sec_cycles, rt_sec_cycles2);
      end
      else begin
        $display("Runtime %0d-bit MODEXP_SEC is constant time: %0d cycles either exponent",
                 RT_KEY_SIZE, rt_sec_cycles);
      end

      // Shortening must reduce latency.
      if (rt_sec_cycles >= sec_cycles) begin
        errors++;
        $display("ERROR: CTRL.KEY_LEN bought nothing: %0d cycles at %0d bits vs %0d at %0d",
                 rt_sec_cycles, RT_KEY_SIZE, sec_cycles, KEY_SIZE);
      end
      else begin
        $display("Runtime %0d-bit MODEXP_SEC on a %0d-bit part: %0d cycles, %0d.%02dx faster than %0d",
                 RT_KEY_SIZE, KEY_SIZE, rt_sec_cycles,
                 sec_cycles / rt_sec_cycles,
                 ((sec_cycles * 100) / rt_sec_cycles) % 100, sec_cycles);
      end

      //--------------------------------------------------------------------
      // Check shortened MUL product reassembly against SystemVerilog
      // arithmetic; no modulus context is needed.
      //--------------------------------------------------------------------
      cfg_shorten = RT_SHORTEN;

      mul_a = '0;
      mul_b = '0;
      mul_a[RT_KEY_SIZE-1:0] = rt_pub_vec[0].n[RT_KEY_SIZE-1:0];
      mul_b[RT_KEY_SIZE-1:0] = rt_pub_vec[0].base[RT_KEY_SIZE-1:0];
      do_mul(mul_a, mul_b, prod, rt_mul_cycles);
      check_mul($sformatf("runtime-%0d MUL", RT_KEY_SIZE), mul_a, mul_b, prod);
      $display("RSA_RESULT rt_mul_cycles %0d", rt_mul_cycles);

      // All-ones operands stress carry across the product's low/high split.
      mul_a = '0;
      mul_b = '0;
      mul_a[RT_KEY_SIZE-1:0] = '1;
      mul_b[RT_KEY_SIZE-1:0] = '1;
      do_mul(mul_a, mul_b, prod, dummy);
      check_mul($sformatf("runtime-%0d MUL all ones", RT_KEY_SIZE),
                mul_a, mul_b, prod);

      if (rt_mul_cycles >= mul_cycles) begin
        errors++;
        $display("ERROR: shortened MUL bought nothing: %0d cycles at %0d bits vs %0d at %0d",
                 rt_mul_cycles, RT_KEY_SIZE, mul_cycles, KEY_SIZE);
      end

      // Native MUL verifies the width is per-command, not sticky.
      cfg_shorten = 2'd0;
      mul_a = '1;
      mul_b = '1;
      do_mul(mul_a, mul_b, prod, dummy);
      check_mul("MUL back at the native key length after a shortened MUL",
                mul_a, mul_b, prod);

      //--------------------------------------------------------------------
      // Restore native-width exponentiation and its original latency.
      //--------------------------------------------------------------------
      cfg_shorten = 2'd0;
      do_ldmod(sec_vec[0].n, dummy);
      do_modexp(CMD_MODEXP_SEC, sec_vec[0].base, sec_vec[0].exponent, res, dummy);
      check_wide("MODEXP_SEC back at the native key length after a shortened run",
                 res, sec_vec[0].result);
      if (dummy !== sec_cycles) begin
        errors++;
        $display("ERROR: native MODEXP_SEC moved after a shortened run: %0d vs %0d",
                 dummy, sec_cycles);
      end
    end

    //----------------------------------------------------------------------
    // Runtime non-half width (3072 on a 4096 part)
    //
    // Ordinary 3072-bit goldens exercise runtime array/sweep geometry and
    // Montgomery targets that cannot be selected by a boolean half_i.
    //----------------------------------------------------------------------
    if (R3_ENABLE) begin
      // The modulus fit check has to follow the 3072 width, not KEY_SIZE/2.
      long_n = r3_pub_vec[0].n;
      long_n[KEY_SIZE-1] = 1'b1;
      cfg_shorten = R3_SHORTEN;
      write_wide(ADDR_MODULUS, MOD_REGS, KEY_WORDS, EXP_SIZE'(long_n));
      issue_cmd(CMD_LDMOD);
      expect_error("3072-on-4096 LDMOD with a bit set above the key length",
                   ERR_MOD_FIT);

      long_n = r3_pub_vec[0].n;
      long_n[R3_KEY_SIZE-1] = 1'b0;
      write_wide(ADDR_MODULUS, MOD_REGS, KEY_WORDS, EXP_SIZE'(long_n));
      issue_cmd(CMD_LDMOD);
      expect_error("3072-on-4096 LDMOD with the top key bit clear", ERR_MOD_FIT);

      // A context built at 3072 is not a 2048 context and is not a 4096 one.
      cfg_shorten = R3_SHORTEN;
      do_ldmod(r3_pub_vec[0].n, r3_ldmod_cycles);
      cfg_shorten = 2'd0;
      issue_cmd(CMD_MODEXP_SEC);
      expect_error("native MODEXP against a 3072-on-4096 context",
                   ERR_BAD_KEYLEN);

      // The context tag must distinguish all widths, not just native vs short.
      cfg_shorten = RT_SHORTEN;
      issue_cmd(CMD_MODEXP_SEC);
      expect_error("2048-wide MODEXP against a 3072-on-4096 context",
                   ERR_BAD_KEYLEN);

      cfg_shorten = R3_SHORTEN;
      do_ldmod(r3_pub_vec[0].n, r3_ldmod_cycles);
      $display("RSA_RESULT r3_ldmod_cycles %0d", r3_ldmod_cycles);

      for (int v = 0; v < NUM_VECTORS; v++) begin
        do_ldmod(r3_pub_vec[v].n, dummy);
        do_modexp(CMD_MODEXP_PUB, r3_pub_vec[v].base, r3_pub_vec[v].exponent, res, r3_pub_cycles);
        check_wide($sformatf("runtime-%0d MODEXP_PUB vector %0d", R3_KEY_SIZE, v),
                   res, r3_pub_vec[v].result);
      end
      $display("RSA_RESULT r3_modexp_pub_cycles %0d", r3_pub_cycles);

      do_ldmod(r3_sec_vec[0].n, dummy);
      do_modexp(CMD_MODEXP_SEC, r3_sec_vec[0].base, r3_sec_vec[0].exponent, res, r3_sec_cycles);
      check_wide($sformatf("runtime-%0d MODEXP_SEC vector 0", R3_KEY_SIZE),
                 res, r3_sec_vec[0].result);
      $display("RSA_RESULT r3_modexp_sec_cycles %0d", r3_sec_cycles);

      // Constant time at the new width, for two different secret exponents.
      do_ldmod(r3_sec_vec[1].n, dummy);
      do_modexp(CMD_MODEXP_SEC, r3_sec_vec[1].base, r3_sec_vec[1].exponent, res, r3_sec_cycles2);
      check_wide($sformatf("runtime-%0d MODEXP_SEC vector 1", R3_KEY_SIZE),
                 res, r3_sec_vec[1].result);
      if (r3_sec_cycles2 !== r3_sec_cycles) begin
        errors++;
        $display("ERROR: 3072-on-4096 MODEXP_SEC is not constant time: %0d vs %0d cycles",
                 r3_sec_cycles, r3_sec_cycles2);
      end
      else begin
        $display("Runtime %0d-bit MODEXP_SEC is constant time: %0d cycles either exponent",
                 R3_KEY_SIZE, r3_sec_cycles);
      end

      // Intermediate latency catches accidental use of 2048/4096 geometry.
      if ((r3_sec_cycles >= sec_cycles) || (r3_sec_cycles <= rt_sec_cycles)) begin
        errors++;
        $display("ERROR: 3072-on-4096 MODEXP_SEC (%0d) is not between 2048 (%0d) and 4096 (%0d)",
                 r3_sec_cycles, rt_sec_cycles, sec_cycles);
      end
      else begin
        $display("Runtime %0d-bit MODEXP_SEC on a %0d-bit part: %0d cycles, %0d.%02dx faster than %0d",
                 R3_KEY_SIZE, KEY_SIZE, r3_sec_cycles,
                 sec_cycles / r3_sec_cycles,
                 ((sec_cycles * 100) / r3_sec_cycles) % 100, sec_cycles);
      end

      // Check MUL reassembly against arithmetic at the non-half 3072+RADIX
      // accumulator shift.
      cfg_shorten = R3_SHORTEN;
      mul_a = '0;
      mul_b = '0;
      mul_a[R3_KEY_SIZE-1:0] = r3_pub_vec[0].n[R3_KEY_SIZE-1:0];
      mul_b[R3_KEY_SIZE-1:0] = r3_pub_vec[0].base[R3_KEY_SIZE-1:0];
      do_mul(mul_a, mul_b, prod, r3_mul_cycles);
      check_mul($sformatf("runtime-%0d MUL", R3_KEY_SIZE), mul_a, mul_b, prod);
      $display("RSA_RESULT r3_mul_cycles %0d", r3_mul_cycles);

      mul_a = '0;
      mul_b = '0;
      mul_a[R3_KEY_SIZE-1:0] = '1;
      mul_b[R3_KEY_SIZE-1:0] = '1;
      do_mul(mul_a, mul_b, prod, dummy);
      check_mul($sformatf("runtime-%0d MUL all ones", R3_KEY_SIZE),
                mul_a, mul_b, prod);

      //--------------------------------------------------------------------
      // 2048-on-4096 CRT uses 1024-bit lanes, not the build's 2048-bit halves.
      // Together with the other passes, cover CRT at 2048/3072/4096 bits.
      //--------------------------------------------------------------------
      if (CRT_ENABLE) begin
        for (int v = 0; v < NUM_CRT_VECTORS; v++) begin
          cfg_shorten = RT_SHORTEN;
          load_crt_key(rt_crt_vec[v]);
          do_ldmod(rt_crt_vec[v].n, rt_crt_ldmod_cycles);
          if (v == 0)
            $display("RSA_RESULT rt_crt_ldmod_cycles %0d", rt_crt_ldmod_cycles);

          write_wide(ADDR_A, A_REGS, KEY_WORDS, EXP_SIZE'(rt_crt_vec[v].base));
          write_wide(ADDR_E, E_REGS, E_REGS, EXP_SIZE'(32'h0001_0001));
          issue_cmd(CMD_MODEXP_SEC_CRT);
          wait_ready(rt_crt_cycles);
          get_status(st);
          if (st[1] !== 1'b1) begin
            errors++;
            $display("ERROR: 2048 MODEXP_SEC_CRT vector %0d did not set VALID (STATUS = %h)",
                     v, st);
          end
          if (st[17:2] !== 16'h0000) begin
            errors++;
            $display("ERROR: 2048 MODEXP_SEC_CRT vector %0d raised ERROR = %h",
                     v, st[17:2]);
          end
          read_result(crt_res);
          check_wide($sformatf("2048 MODEXP_SEC_CRT vector %0d", v),
                     crt_res, rt_crt_vec[v].m);

          if (v == 0) begin
            rt_crt_cycles2 = rt_crt_cycles;
            $display("RSA_RESULT rt_modexp_sec_crt_cycles %0d", rt_crt_cycles);
          end
          else if (rt_crt_cycles !== rt_crt_cycles2) begin
            errors++;
            $display("ERROR: 2048 MODEXP_SEC_CRT is not constant time: %0d vs %0d cycles",
                     rt_crt_cycles, rt_crt_cycles2);
          end
          else begin
            $display("Runtime %0d-bit MODEXP_SEC_CRT is constant time: %0d cycles either key",
                     RT_KEY_SIZE, rt_crt_cycles2);
          end
        end

        if (rt_crt_cycles2 >= crt_cycles2) begin
          errors++;
          $display("ERROR: 2048 MODEXP_SEC_CRT (%0d) is not faster than 4096 (%0d)",
                   rt_crt_cycles2, crt_cycles2);
        end
        else begin
          $display("Runtime %0d-bit MODEXP_SEC_CRT: %0d cycles vs %0d at %0d bits (%0d/100 x)",
                   RT_KEY_SIZE, rt_crt_cycles2, crt_cycles2, KEY_SIZE,
                   (crt_cycles2 * 100) / rt_crt_cycles2);
        end
      end

      //--------------------------------------------------------------------
      // 3072-on-4096 CRT uses 1536-bit lanes and must beat native CRT latency.
      //--------------------------------------------------------------------
      if (CRT_ENABLE) begin
        for (int v = 0; v < NUM_CRT_VECTORS; v++) begin
          cfg_shorten = R3_SHORTEN;
          load_crt_key(r3_crt_vec[v]);
          do_ldmod(r3_crt_vec[v].n, r3_crt_ldmod_cycles);
          if (v == 0)
            $display("RSA_RESULT r3_crt_ldmod_cycles %0d", r3_crt_ldmod_cycles);

          write_wide(ADDR_A, A_REGS, KEY_WORDS, EXP_SIZE'(r3_crt_vec[v].base));
          write_wide(ADDR_E, E_REGS, E_REGS, EXP_SIZE'(32'h0001_0001));
          issue_cmd(CMD_MODEXP_SEC_CRT);
          wait_ready(r3_crt_cycles);
          get_status(st);
          if (st[1] !== 1'b1) begin
            errors++;
            $display("ERROR: 3072 MODEXP_SEC_CRT vector %0d did not set VALID (STATUS = %h)",
                     v, st);
          end
          if (st[17:2] !== 16'h0000) begin
            errors++;
            $display("ERROR: 3072 MODEXP_SEC_CRT vector %0d raised ERROR = %h",
                     v, st[17:2]);
          end
          read_result(crt_res);
          check_wide($sformatf("3072 MODEXP_SEC_CRT vector %0d", v),
                     crt_res, r3_crt_vec[v].m);

          if (v == 0) begin
            r3_crt_cycles2 = r3_crt_cycles;
            $display("RSA_RESULT r3_modexp_sec_crt_cycles %0d", r3_crt_cycles);
          end
          else if (r3_crt_cycles !== r3_crt_cycles2) begin
            errors++;
            $display("ERROR: 3072 MODEXP_SEC_CRT is not constant time: %0d vs %0d cycles",
                     r3_crt_cycles, r3_crt_cycles2);
          end
          else begin
            $display("Runtime %0d-bit MODEXP_SEC_CRT is constant time: %0d cycles either key",
                     R3_KEY_SIZE, r3_crt_cycles2);
          end
        end

        // Require lower latency; result checks above also catch wrong lane
        // geometry that causes Bellcore verification to withhold the result.
        if (r3_crt_cycles2 >= crt_cycles2) begin
          errors++;
          $display("ERROR: 3072 MODEXP_SEC_CRT (%0d) is not faster than 4096 (%0d)",
                   r3_crt_cycles2, crt_cycles2);
        end
        else begin
          $display("Runtime %0d-bit MODEXP_SEC_CRT: %0d cycles vs %0d at %0d bits (%0d/100 x)",
                   R3_KEY_SIZE, r3_crt_cycles2, crt_cycles2, KEY_SIZE,
                   (crt_cycles2 * 100) / r3_crt_cycles2);
        end
      end

      // Verify native width and latency recover after a 3072-bit run.
      cfg_shorten = 2'd0;
      do_ldmod(sec_vec[0].n, dummy);
      do_modexp(CMD_MODEXP_SEC, sec_vec[0].base, sec_vec[0].exponent, res, dummy);
      check_wide("MODEXP_SEC back at the native key length after a 3072 run",
                 res, sec_vec[0].result);
      if (dummy !== sec_cycles) begin
        errors++;
        $display("ERROR: native MODEXP_SEC moved after a 3072 run: %0d vs %0d",
                 dummy, sec_cycles);
      end
    end

    //----------------------------------------------------------------------
    // ZEROIZE must clear the operand and result apertures and the context.
    //----------------------------------------------------------------------
    // MODULUS_VALID must transition from loaded (1) to cleared (0) on ZEROIZE.
    ahb_read(ADDR_STATUS, rd);
    if (rd[18] !== 1'b1) begin
      errors++;
      $display("ERROR: STATUS.MODULUS_VALID reads 0 with a context loaded (STATUS = %h)", rd);
    end

    ahb_write(ADDR_CTRL, 32'h0000_0080);  // ZEROIZE is bit 7
    repeat (5) @(posedge clk);

    ahb_read(ADDR_STATUS, rd);
    if (rd[18] !== 1'b0) begin
      errors++;
      $display("ERROR: ZEROIZE left STATUS.MODULUS_VALID set (STATUS = %h)", rd);
    end

    for (int w = 0; w < KEY_WORDS; w++) begin
      ahb_read(ADDR_RESULT + 32'(4*(RES_REGS - KEY_WORDS + w)), rd);
      if (rd !== 32'h0) begin
        errors++;
        $display("ERROR: ZEROIZE left RESULT word %0d = %h", w, rd);
      end
      ahb_read(ADDR_MODULUS + 32'(4*(MOD_REGS - KEY_WORDS + w)), rd);
      if (rd !== 32'h0) begin
        errors++;
        $display("ERROR: ZEROIZE left MODULUS word %0d = %h", w, rd);
      end
      ahb_read(ADDR_A + 32'(4*(A_REGS - KEY_WORDS + w)), rd);
      if (rd !== 32'h0) begin
        errors++;
        $display("ERROR: ZEROIZE left A word %0d = %h", w, rd);
      end
      ahb_read(ADDR_B + 32'(4*(B_REGS - KEY_WORDS + w)), rd);
      if (rd !== 32'h0) begin
        errors++;
        $display("ERROR: ZEROIZE left B word %0d = %h", w, rd);
      end
    end
    for (int w = 0; w < 2*KEY_WORDS; w++) begin
      ahb_read(ADDR_PRODUCT + 32'(4*(PROD_REGS - 2*KEY_WORDS + w)), rd);
      if (rd !== 32'h0) begin
        errors++;
        $display("ERROR: ZEROIZE left PRODUCT word %0d = %h", w, rd);
      end
    end
    // The modulus context must be gone too.
    issue_cmd(CMD_MODEXP_PUB);
    expect_error("MODEXP after ZEROIZE", ERR_NO_CONTEXT);

    //----------------------------------------------------------------------
    // Debug unlock or scan-mode switch must zeroize without software action.
    //----------------------------------------------------------------------
    do_ldmod(pub_vec[0].n, ldmod_cycles);
    debug_unlock = 1'b1;
    repeat (5) @(posedge clk);
    debug_unlock = 1'b0;
    repeat (5) @(posedge clk);
    for (int w = 0; w < KEY_WORDS; w++) begin
      ahb_read(ADDR_MODULUS + 32'(4*(MOD_REGS - KEY_WORDS + w)), rd);
      if (rd !== 32'h0) begin
        errors++;
        $display("ERROR: debug unlock left MODULUS word %0d = %h", w, rd);
      end
    end
    issue_cmd(CMD_MODEXP_PUB);
    expect_error("MODEXP after debug unlock", ERR_NO_CONTEXT);

    $display("---------------------------------------------");
    if (errors == 0) $display("* TESTCASE PASSED");
    else             $display("* TESTCASE FAILED with %0d errors", errors);
    $display("---------------------------------------------");
    $finish;
  end

endmodule
