//----------------------------------------------------------------------
// RSA_in_kat_sequence
//
// Replays the NIST ACVP RSA signature-primitive known-answer vectors through
// the register interface.
//
// Real RSA keys complement random Montgomery operands with signature-domain
// operand distributions, including bases near the modulus.
//
// Share rsa_top_tb's vectors, staged by uvmf_rsa/config/compile.yml pre_exec.
//
// Format: seven hex lines; lines 0/1/2/6 are base, exponent, n and result.
// Read only the operands; RSA_predictor independently recomputes the result.
//----------------------------------------------------------------------

class RSA_in_kat_sequence #(
      int AHB_DATA_WIDTH = 32,
      int AHB_ADDR_WIDTH = 32
      )
  extends RSA_in_sequence_base #(
      .AHB_DATA_WIDTH(AHB_DATA_WIDTH),
      .AHB_ADDR_WIDTH(AHB_ADDR_WIDTH)
      );

  `uvm_object_param_utils( RSA_in_kat_sequence #(
                           AHB_DATA_WIDTH,
                           AHB_ADDR_WIDTH
                           ))

  // Set before start(); selects the runtime width and vector file.
  rsa_in_keylen_transactions kat_keylen = rsa_keylen_4096;

  // Replay limit, defaulting to all 13 vectors.
  int unsigned kat_count = 13;

  function new(string name = "");
    super.new(name);
  endfunction: new

  task body();
    int unsigned                      kbits;
    string                            fname;
    integer                           fin;
    integer                           rv;
    int unsigned                      line_cnt;
    int unsigned                      idx;
    bit [RSA_IN_MAX_KEY_SIZE-1:0]     val;
    bit [RSA_IN_MAX_KEY_SIZE-1:0]     v_base;
    bit [RSA_IN_MAX_KEY_SIZE-1:0]     v_exp;
    bit [RSA_IN_MAX_KEY_SIZE-1:0]     v_n;

    kbits = rsa_keylen_bits(kat_keylen);
    fname = $sformatf("rsa_modexp_kat_pub_vectors_13_key_%0d_word_64.hex", kbits);

    fin = $fopen(fname, "r");
    if (fin == 0) begin
      `uvm_fatal("KAT", $sformatf("cannot open ACVP vector file %s -- is the pre_exec staging hook in uvmf_rsa/config/compile.yml present?", fname))
    end

    line_cnt = 0;
    idx      = 0;
    v_base   = '0;
    v_exp    = '0;
    v_n      = '0;

    while ((!$feof(fin)) && (idx < kat_count)) begin
      rv = $fscanf(fin, "%h\n", val);
      if (rv != 1) break;
      case (line_cnt % 7)
        0: v_base = val;
        1: v_exp  = val;
        2: v_n    = val;
        6: begin
             req = RSA_in_transaction#(
                       .AHB_DATA_WIDTH(AHB_DATA_WIDTH),
                       .AHB_ADDR_WIDTH(AHB_ADDR_WIDTH)
                       )::type_id::create("req");
             start_item(req);
             // Preserve ACVP operands while randomizing test/op/keylen.
             req.fixed_operands = 1'b1;
             if (!req.randomize() with { test   == rsa_normal_test;
                                         op     == rsa_op_modexp_pub;
                                         keylen == kat_keylen; })
               `uvm_fatal("KAT", "RSA_in_kat_sequence::body()-randomization failed")
             req.modulus  = v_n;
             req.base     = v_base;
             req.exponent = v_exp;
             // exp_len is an MSB index, not a count: 16 for e = 65537.
             req.exp_len  = 16;
             finish_item(req);
             idx++;
           end
        default: ;
      endcase
      line_cnt++;
    end
    $fclose(fin);

    if (idx != kat_count) begin
      `uvm_error("KAT", $sformatf("%s yielded %0d vectors, expected %0d",
                                  fname, idx, kat_count))
    end
    else begin
      `uvm_info("KAT", $sformatf("replayed %0d ACVP vectors at %0d bits",
                                 idx, kbits), UVM_LOW)
    end
  endtask

endclass: RSA_in_kat_sequence
