//----------------------------------------------------------------------
// RSA_in_err_sequence
//
// Exercise tessera_rsa_ctrl's refusal priority chain, checking the exact error index.
// Each BFM recipe satisfies earlier preconditions to isolate its target rung.
// Test both ERR_BAD_KEYLEN causes: unsupported encoding and context mismatch.
// ERR_CRT_FAIL uses valid vector key material, with qinv corrupted after LDMOD.
// Refusals leave RESULT stale: suppress both output activity and predictions.
//----------------------------------------------------------------------

class RSA_in_err_sequence #(
      int AHB_DATA_WIDTH = 32,
      int AHB_ADDR_WIDTH = 32
      )
  extends RSA_in_sequence_base #(
      .AHB_DATA_WIDTH(AHB_DATA_WIDTH),
      .AHB_ADDR_WIDTH(AHB_ADDR_WIDTH)
      );

  `uvm_object_param_utils( RSA_in_err_sequence #(
                           AHB_DATA_WIDTH,
                           AHB_ADDR_WIDTH
                           ))

  // Bench-selected runtime width for width-dependent refusal checks.
  rsa_in_keylen_transactions err_keylen = rsa_keylen_2048;

  // BFM recipe selectors: ERROR-field indices, plus 16 for context mismatch.
  localparam int unsigned ERR_CASE_BAD_CMD          = 0;
  localparam int unsigned ERR_CASE_NO_CONTEXT       = 1;
  localparam int unsigned ERR_CASE_BAD_MOD          = 2;
  localparam int unsigned ERR_CASE_BAD_BASE         = 3;
  localparam int unsigned ERR_CASE_CRT_UNAVAIL      = 4;
  localparam int unsigned ERR_CASE_MOD_RANGE        = 5;
  // No case 6: hardware derives the ladder length from RSA_E.
  localparam int unsigned ERR_CASE_CRT_FAIL         = 7;
  localparam int unsigned ERR_CASE_BAD_KEYLEN       = 8;
  localparam int unsigned ERR_CASE_MOD_FIT          = 9;
  localparam int unsigned ERR_CASE_KEYLEN_MISMATCH  = 16;

  function new(string name = "");
    super.new(name);
  endfunction: new

  // Supply random legal operands; the BFM constructs any case-specific violation.
  task automatic drive_case(input int unsigned err_case);
    req = RSA_in_transaction#(
              .AHB_DATA_WIDTH(AHB_DATA_WIDTH),
              .AHB_ADDR_WIDTH(AHB_ADDR_WIDTH)
              )::type_id::create("req");
    start_item(req);
    req.allow_err = 1'b1;
    if (!req.randomize() with { test   == rsa_err_test;
                                op     == rsa_op_modexp_pub;
                                keylen == err_keylen; })
      `uvm_fatal("ERRINJ", "RSA_in_err_sequence::drive_case()-randomization failed")
    req.err_case = 32'(err_case);
    finish_item(req);
  endtask

  // Load a valid CRT vector so the BFM can isolate a qinv conformance failure.
  task automatic drive_crt_fail_case();
    int unsigned                  kbits;
    string                        fname;
    integer                       fin;
    integer                       rv;
    int unsigned                  line_cnt;
    bit                           got_one;
    bit [RSA_IN_MAX_KEY_SIZE-1:0] val;
    bit [RSA_IN_MAX_KEY_SIZE-1:0] v_n, v_d, v_p, v_q, v_dp, v_dq, v_qinv, v_base;

    kbits = rsa_keylen_bits(err_keylen);
    fname = $sformatf("rsa_crt_vectors_2_key_%0d_word_64.hex", kbits);

    fin = $fopen(fname, "r");
    if (fin == 0) begin
      `uvm_fatal("ERRINJ", $sformatf("cannot open CRT vector file %s", fname))
    end

    line_cnt = 0;
    got_one  = 1'b0;
    v_n = '0; v_d = '0; v_p = '0; v_q = '0;
    v_dp = '0; v_dq = '0; v_qinv = '0; v_base = '0;

    while ((!$feof(fin)) && (!got_one)) begin
      rv = $fscanf(fin, "%h\n", val);
      if (rv != 1) break;
      case (line_cnt % 9)
        0: v_n    = val;
        1: v_d    = val;
        2: v_p    = val;
        3: v_q    = val;
        4: v_dp   = val;
        5: v_dq   = val;
        6: v_qinv = val;
        7: v_base = val;
        8: got_one = 1'b1;
        default: ;
      endcase
      line_cnt++;
    end
    $fclose(fin);

    if (!got_one) begin
      `uvm_error("ERRINJ", $sformatf("%s yielded no complete CRT vector", fname))
      return;
    end

    req = RSA_in_transaction#(
              .AHB_DATA_WIDTH(AHB_DATA_WIDTH),
              .AHB_ADDR_WIDTH(AHB_ADDR_WIDTH)
              )::type_id::create("req");
    start_item(req);
    req.fixed_operands = 1'b1;
    req.allow_err      = 1'b1;
    // Enable the guarded CRT opcode before randomization.
    req.allow_crt      = 1'b1;
    if (!req.randomize() with { test   == rsa_err_test;
                                op     == rsa_op_modexp_sec_crt;
                                keylen == err_keylen; })
      `uvm_fatal("ERRINJ", "RSA_in_err_sequence::drive_crt_fail_case()-randomization failed")
    req.modulus  = v_n;
    req.base     = v_base;
    req.exponent = v_d;
    req.exp_len  = kbits - 1;
    req.p        = v_p   [RSA_IN_MAX_KEY_SIZE/2-1:0];
    req.q        = v_q   [RSA_IN_MAX_KEY_SIZE/2-1:0];
    req.dp       = v_dp  [RSA_IN_MAX_KEY_SIZE/2-1:0];
    req.dq       = v_dq  [RSA_IN_MAX_KEY_SIZE/2-1:0];
    // Pass valid qinv; the BFM corrupts it only after LDMOD arms CRT.
    // Earlier corruption would hit ERR_NO_CONTEXT instead of ERR_CRT_FAIL.
    req.qinv     = v_qinv[RSA_IN_MAX_KEY_SIZE/2-1:0];
    req.err_case = 32'(ERR_CASE_CRT_FAIL);
    finish_item(req);
  endtask

  task body();
    `uvm_info("ERRINJ",
              $sformatf("driving deliberate refusals at %0d bits",
                        rsa_keylen_bits(err_keylen)), UVM_LOW)

    // Run the reset-based no-context case first; later cases build their contexts.
    drive_case(ERR_CASE_NO_CONTEXT);
    drive_case(ERR_CASE_BAD_CMD);
    drive_case(ERR_CASE_BAD_MOD);
    drive_case(ERR_CASE_MOD_FIT);
    drive_case(ERR_CASE_MOD_RANGE);
    drive_case(ERR_CASE_BAD_BASE);

    // CRT availability is build-time only. ERR_CRT_UNAVAIL requires a build
    // without CRT; this bench enables RSA_CRT_ENABLE_CONFIG.
    //
    // Reserved CTRL.KEY_LEN encoding 2'b11 reaches ERR_BAD_KEYLEN at any size.
    drive_case(ERR_CASE_BAD_KEYLEN);
    drive_case(ERR_CASE_KEYLEN_MISMATCH);

    drive_crt_fail_case();
  endtask

endclass: RSA_in_err_sequence
