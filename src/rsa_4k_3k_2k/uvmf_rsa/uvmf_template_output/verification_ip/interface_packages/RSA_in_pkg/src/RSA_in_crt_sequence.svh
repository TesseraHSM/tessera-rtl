//----------------------------------------------------------------------
// RSA_in_crt_sequence
//
// Drives MODEXP_SEC_CRT from the checked-in CRT vector files.
//
// CRT requires genuine primes and matching dp/dq/qinv. Reuse rsa_top_tb's
// validated vectors rather than generating expensive primes in simulation.
//
// Format: nine full-key-width hex lines: n, d, p, q, dp, dq, qinv, base, m.
// Strip zero padding from the half-width CRT fields. Ignore golden m:
// RSA_predictor independently computes base^d mod n without CRT.
//----------------------------------------------------------------------

class RSA_in_crt_sequence #(
      int AHB_DATA_WIDTH = 32,
      int AHB_ADDR_WIDTH = 32
      )
  extends RSA_in_sequence_base #(
      .AHB_DATA_WIDTH(AHB_DATA_WIDTH),
      .AHB_ADDR_WIDTH(AHB_ADDR_WIDTH)
      );

  `uvm_object_param_utils( RSA_in_crt_sequence #(
                           AHB_DATA_WIDTH,
                           AHB_ADDR_WIDTH
                           ))

  rsa_in_keylen_transactions crt_keylen = rsa_keylen_4096;

  // Replay both vectors per file; 4096-bit CRT can take ~173k cycles.
  int unsigned crt_count = 2;

  function new(string name = "");
    super.new(name);
  endfunction: new

  task body();
    int unsigned                    kbits;
    string                          fname;
    integer                         fin;
    integer                         rv;
    int unsigned                    line_cnt;
    int unsigned                    idx;
    bit [RSA_IN_MAX_KEY_SIZE-1:0]   val;
    bit [RSA_IN_MAX_KEY_SIZE-1:0]   v_n, v_d, v_p, v_q, v_dp, v_dq, v_qinv, v_base;

    kbits = rsa_keylen_bits(crt_keylen);
    fname = $sformatf("rsa_crt_vectors_2_key_%0d_word_64.hex", kbits);

    fin = $fopen(fname, "r");
    if (fin == 0) begin
      `uvm_fatal("CRT", $sformatf("cannot open CRT vector file %s -- is the pre_exec staging hook in uvmf_rsa/config/compile.yml present?", fname))
    end

    line_cnt = 0;
    idx      = 0;
    v_n = '0; v_d = '0; v_p = '0; v_q = '0;
    v_dp = '0; v_dq = '0; v_qinv = '0; v_base = '0;

    while ((!$feof(fin)) && (idx < crt_count)) begin
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
        8: begin   // line 8 is the golden m; deliberately not read into a field
             req = RSA_in_transaction#(
                       .AHB_DATA_WIDTH(AHB_DATA_WIDTH),
                       .AHB_ADDR_WIDTH(AHB_ADDR_WIDTH)
                       )::type_id::create("req");
             start_item(req);
             req.fixed_operands = 1'b1;
             req.allow_crt      = 1'b1;
             if (!req.randomize() with { test   == rsa_normal_test;
                                         op     == rsa_op_modexp_sec_crt;
                                         keylen == crt_keylen; })
               `uvm_fatal("CRT", "RSA_in_crt_sequence::body()-randomization failed")
             req.modulus  = v_n;
             req.base     = v_base;
             req.exponent = v_d;
             // Private-exponent MSB index for the predictor, not the driver.
             // The DUT's Bellcore check uses the public exponent instead.
             req.exp_len  = kbits - 1;
             // Strip padding from half-width CRT fields. p/q must have their
             // top bit set, bounding q < 2p for Garner's reduction.
             req.p        = v_p   [RSA_IN_MAX_KEY_SIZE/2-1:0];
             req.q        = v_q   [RSA_IN_MAX_KEY_SIZE/2-1:0];
             req.dp       = v_dp  [RSA_IN_MAX_KEY_SIZE/2-1:0];
             req.dq       = v_dq  [RSA_IN_MAX_KEY_SIZE/2-1:0];
             req.qinv     = v_qinv[RSA_IN_MAX_KEY_SIZE/2-1:0];
             finish_item(req);
             idx++;
           end
        default: ;
      endcase
      line_cnt++;
    end
    $fclose(fin);

    if (idx != crt_count) begin
      `uvm_error("CRT", $sformatf("%s yielded %0d vectors, expected %0d",
                                  fname, idx, crt_count))
    end
    else begin
      `uvm_info("CRT", $sformatf("replayed %0d CRT vectors at %0d bits",
                                 idx, kbits), UVM_LOW)
    end
  endtask

endclass: RSA_in_crt_sequence
