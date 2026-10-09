//----------------------------------------------------------------------
// Created with uvmf_gen version 2022.3
//----------------------------------------------------------------------
// pragma uvmf custom header begin
// pragma uvmf custom header end
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//     
// DESCRIPTION: This class defines the variables required for an RSA_in
//    transaction.  Class variables to be displayed in waveform transaction
//    viewing are added to the transaction viewing stream in the add_to_wave
//    function.
//
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//
class RSA_in_transaction #(
      int AHB_ADDR_WIDTH = 32,
      int AHB_DATA_WIDTH = 32
      )
 extends uvmf_transaction_base;

  `uvm_object_param_utils( RSA_in_transaction #(
                           AHB_ADDR_WIDTH,
                           AHB_DATA_WIDTH
                           )
)

  rand rsa_in_test_transactions test ;
  rand rsa_in_op_transactions op ;
  rand rsa_in_keylen_transactions keylen ;

  //--------------------------------------------------------------------------
  // Generate wide operands procedurally for seed-reproducible stimulus without
  // expensive solver arithmetic. fixed_operands preserves sequence-supplied values.
  // MUL reuses base/exponent as factors and needs no modulus.
  //--------------------------------------------------------------------------
  bit                          fixed_operands = 1'b0;
  bit [RSA_IN_MAX_KEY_SIZE-1:0] modulus ;
  bit [RSA_IN_MAX_KEY_SIZE-1:0] base ;
  bit [RSA_IN_MAX_KEY_SIZE-1:0] exponent ;
  bit [31:0]                   exp_len ;

  //--------------------------------------------------------------------------
  // Half-width CRT key material from validated prime vectors. p/q must have
  // their MSB set, bounding q < 2p for Garner's reduction.
  // Only the initiator struct carries these write-only-aperture operands;
  // the predictor independently computes base^d mod n from exponent.
  //--------------------------------------------------------------------------
  bit [RSA_IN_MAX_KEY_SIZE/2-1:0] p ;
  bit [RSA_IN_MAX_KEY_SIZE/2-1:0] q ;
  bit [RSA_IN_MAX_KEY_SIZE/2-1:0] dp ;
  bit [RSA_IN_MAX_KEY_SIZE/2-1:0] dq ;
  bit [RSA_IN_MAX_KEY_SIZE/2-1:0] qinv ;

  //--------------------------------------------------------------------------
  // Allow CRT only for directed sequences supplying a valid factorization.
  //--------------------------------------------------------------------------
  bit allow_crt = 1'b0;

  //--------------------------------------------------------------------------
  // Enable deliberate refusals only for directed error sequences.
  //--------------------------------------------------------------------------
  bit allow_err = 1'b0;

  // Error recipe selector and expected cmd_error index for rsa_err_test.
  bit [31:0] err_case = 32'd0;

  //Constraints for the transaction variables:
  constraint rsa_valid_test_contraints { test inside {rsa_reset_test, rsa_normal_test, rsa_otf_reset_test, rsa_err_test};
                                         (test == rsa_err_test) -> allow_err; }
  constraint rsa_valid_op_constraints { op inside {rsa_op_mul, rsa_op_ldmod, rsa_op_modexp_pub, rsa_op_modexp_sec, rsa_op_modexp_sec_crt};
                                        (op == rsa_op_modexp_sec_crt) -> allow_crt; }
  constraint rsa_valid_keylen_constraints { keylen inside {rsa_keylen_2048, rsa_keylen_3072, rsa_keylen_4096}; }

  // ****************************************************************************
  // FUNCTION: gen_operands()
  // Procedural stimulus generation for the wide operands.  Called from
  // post_randomize() unless the sequence supplied its own operands.
  //
  function void gen_operands();
    int unsigned bits  = rsa_keylen_bits(keylen);
    int unsigned words = bits / 32;

    modulus  = '0;
    base     = '0;
    exponent = '0;
    p        = '0;
    q        = '0;
    dp       = '0;
    dq       = '0;
    qinv     = '0;

    for (int w = 0; w < words; w++) begin
      base[w*32 +: 32]     = $urandom();
      exponent[w*32 +: 32] = $urandom();
    end

    if (op == rsa_op_mul) begin
      // Plain multiply: no modulus, no reduction, any two factors are legal.
      // exp_len is unused by MUL but must not be left stale.
      exp_len = bits - 1;
      return;
    end

    for (int w = 0; w < words; w++) modulus[w*32 +: 32] = $urandom();
    // Montgomery needs an odd modulus; set its top bit to occupy the chosen width.
    modulus[0]      = 1'b1;
    modulus[bits-1] = 1'b1;

    // Keep normal stimulus reduced below the modulus.
    base = base % modulus;

    // exp_len is an MSB index; the predictor scans exp_len+1 bits.
    if (op == rsa_op_modexp_pub) begin
      // Public exponent: the canonical 65537, whose MSB is bit 16.
      exponent = 'h10001;
      exp_len  = 16;
    end
    else begin
      exponent[bits-1] = 1'b1;   // make the exponent genuinely `bits` long
      exponent[0]      = 1'b1;   // odd, as a real private exponent is
      exp_len          = bits - 1;
    end
  endfunction

  function void post_randomize();
    if (!fixed_operands) gen_operands();
  endfunction

  // pragma uvmf custom class_item_additional begin
  // pragma uvmf custom class_item_additional end

  //*******************************************************************
  //*******************************************************************
  // Macros that define structs and associated functions are
  // located in RSA_in_macros.svh

  //*******************************************************************
  // Monitor macro used by RSA_in_monitor and RSA_in_monitor_bfm
  // This struct is defined in RSA_in_macros.svh
  `RSA_in_MONITOR_STRUCT
    RSA_in_monitor_s RSA_in_monitor_struct;
  //*******************************************************************
  // FUNCTION: to_monitor_struct()
  // This function packs transaction variables into a RSA_in_monitor_s
  // structure.  The function returns the handle to the RSA_in_monitor_struct.
  // This function is defined in RSA_in_macros.svh
  `RSA_in_TO_MONITOR_STRUCT_FUNCTION 
  //*******************************************************************
  // FUNCTION: from_monitor_struct()
  // This function unpacks the struct provided as an argument into transaction 
  // variables of this class.
  // This function is defined in RSA_in_macros.svh
  `RSA_in_FROM_MONITOR_STRUCT_FUNCTION 

  //*******************************************************************
  // Initiator macro used by RSA_in_driver and RSA_in_driver_bfm
  // to communicate initiator driven data to RSA_in_driver_bfm.
  // This struct is defined in RSA_in_macros.svh
  `RSA_in_INITIATOR_STRUCT
    RSA_in_initiator_s RSA_in_initiator_struct;
  //*******************************************************************
  // FUNCTION: to_initiator_struct()
  // This function packs transaction variables into a RSA_in_initiator_s
  // structure.  The function returns the handle to the RSA_in_initiator_struct.
  // This function is defined in RSA_in_macros.svh
  `RSA_in_TO_INITIATOR_STRUCT_FUNCTION  
  //*******************************************************************
  // FUNCTION: from_initiator_struct()
  // This function unpacks the struct provided as an argument into transaction 
  // variables of this class.
  // This function is defined in RSA_in_macros.svh
  `RSA_in_FROM_INITIATOR_STRUCT_FUNCTION 

  //*******************************************************************
  // Responder macro used by RSA_in_driver and RSA_in_driver_bfm
  // to communicate Responder driven data to RSA_in_driver_bfm.
  // This struct is defined in RSA_in_macros.svh
  `RSA_in_RESPONDER_STRUCT
    RSA_in_responder_s RSA_in_responder_struct;
  //*******************************************************************
  // FUNCTION: to_responder_struct()
  // This function packs transaction variables into a RSA_in_responder_s
  // structure.  The function returns the handle to the RSA_in_responder_struct.
  // This function is defined in RSA_in_macros.svh
  `RSA_in_TO_RESPONDER_STRUCT_FUNCTION 
  //*******************************************************************
  // FUNCTION: from_responder_struct()
  // This function unpacks the struct provided as an argument into transaction 
  // variables of this class.
  // This function is defined in RSA_in_macros.svh
  `RSA_in_FROM_RESPONDER_STRUCT_FUNCTION 
  // ****************************************************************************
  // FUNCTION : new()
  // This function is the standard SystemVerilog constructor.
  //
  function new( string name = "" );
    super.new( name );
  endfunction

  // ****************************************************************************
  // FUNCTION: convert2string()
  // This function converts all variables in this class to a single string for 
  // logfile reporting.
  //
  virtual function string convert2string();
    // pragma uvmf custom convert2string begin
    // UVMF_CHANGE_ME : Customize format if desired.
    return $sformatf("test:%0s op:%0s keylen:%0s exp_len:%0d n:0x%0x b:0x%0x e:0x%0x",
                     test.name(), op.name(), keylen.name(), exp_len,
                     modulus, base, exponent);
    // pragma uvmf custom convert2string end
  endfunction

  //*******************************************************************
  // FUNCTION: do_print()
  // This function is automatically called when the .print() function
  // is called on this class.
  //
  virtual function void do_print(uvm_printer printer);
    // pragma uvmf custom do_print begin
    // UVMF_CHANGE_ME : Current contents of do_print allows for the use of UVM 1.1d, 1.2 or P1800.2.
    // Update based on your own printing preference according to your preferred UVM version
    $display(convert2string());
    // pragma uvmf custom do_print end
  endfunction

  //*******************************************************************
  // FUNCTION: do_compare()
  // This function is automatically called when the .compare() function
  // is called on this class.
  //
  virtual function bit do_compare (uvm_object rhs, uvm_comparer comparer);
    RSA_in_transaction #(
        .AHB_ADDR_WIDTH(AHB_ADDR_WIDTH),
        .AHB_DATA_WIDTH(AHB_DATA_WIDTH)
        )
 RHS;
    if (!$cast(RHS,rhs)) return 0;
    // pragma uvmf custom do_compare begin
    // UVMF_CHANGE_ME : Eliminate comparison of variables not to be used for compare
    return (super.do_compare(rhs,comparer)
            &&(this.test == RHS.test)
            &&(this.op == RHS.op)
            &&(this.keylen == RHS.keylen)
            &&(this.modulus == RHS.modulus)
            &&(this.base == RHS.base)
            &&(this.exponent == RHS.exponent)
            &&(this.exp_len == RHS.exp_len)
            );
    // pragma uvmf custom do_compare end
  endfunction

  //*******************************************************************
  // FUNCTION: do_copy()
  // This function is automatically called when the .copy() function
  // is called on this class.
  //
  virtual function void do_copy (uvm_object rhs);
    RSA_in_transaction #(
        .AHB_ADDR_WIDTH(AHB_ADDR_WIDTH),
        .AHB_DATA_WIDTH(AHB_DATA_WIDTH)
        )
 RHS;
    assert($cast(RHS,rhs));
    // pragma uvmf custom do_copy begin
    super.do_copy(rhs);
    this.test = RHS.test;
    this.op = RHS.op;
    this.keylen = RHS.keylen;
    this.fixed_operands = RHS.fixed_operands;
    this.modulus = RHS.modulus;
    this.base = RHS.base;
    this.exponent = RHS.exponent;
    this.exp_len = RHS.exp_len;
    // pragma uvmf custom do_copy end
  endfunction

  // ****************************************************************************
  // FUNCTION: add_to_wave()
  // This function is used to display variables in this class in the waveform 
  // viewer.  The start_time and end_time variables must be set before this 
  // function is called.  If the start_time and end_time variables are not set
  // the transaction will be hidden at 0ns on the waveform display.
  // 
  virtual function void add_to_wave(int transaction_viewing_stream_h);
    `ifdef QUESTA
    if (transaction_view_h == 0) begin
      transaction_view_h = $begin_transaction(transaction_viewing_stream_h,"RSA_in_transaction",start_time);
    end
    super.add_to_wave(transaction_view_h);
    // pragma uvmf custom add_to_wave begin
    // UVMF_CHANGE_ME : Color can be applied to transaction entries based on content, example below
    // case()
    //   1 : $add_color(transaction_view_h,"red");
    //   default : $add_color(transaction_view_h,"grey");
    // endcase
    // UVMF_CHANGE_ME : Eliminate transaction variables not wanted in transaction viewing in the waveform viewer
    $add_attribute(transaction_view_h,test,"test");
    $add_attribute(transaction_view_h,op,"op");
    $add_attribute(transaction_view_h,keylen,"keylen");
    $add_attribute(transaction_view_h,exp_len,"exp_len");
    // pragma uvmf custom add_to_wave end
    $end_transaction(transaction_view_h,end_time);
    $free_transaction(transaction_view_h);
    `endif // QUESTA
  endfunction

endclass

// pragma uvmf custom external begin
// pragma uvmf custom external end
