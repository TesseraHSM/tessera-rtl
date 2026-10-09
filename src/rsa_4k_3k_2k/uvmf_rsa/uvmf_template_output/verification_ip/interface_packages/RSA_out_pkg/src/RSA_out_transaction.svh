//----------------------------------------------------------------------
// Created with uvmf_gen version 2022.3
//----------------------------------------------------------------------
// pragma uvmf custom header begin
// pragma uvmf custom header end
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//     
// DESCRIPTION: This class defines the variables required for an RSA_out
//    transaction.  Class variables to be displayed in waveform transaction
//    viewing are added to the transaction viewing stream in the add_to_wave
//    function.
//
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//
class RSA_out_transaction #(
      int AHB_ADDR_WIDTH = 32,
      int AHB_DATA_WIDTH = 32,
      int OUTPUT_TEXT_WIDTH = 4096
      )
 extends uvmf_transaction_base;

  `uvm_object_param_utils( RSA_out_transaction #(
                           AHB_ADDR_WIDTH,
                           AHB_DATA_WIDTH,
                           OUTPUT_TEXT_WIDTH
                           )
)

  bit [OUTPUT_TEXT_WIDTH-1:0] rsa_result ;
  bit [OUTPUT_TEXT_WIDTH-1:0] rsa_product_hi ;
  bit [OUTPUT_TEXT_WIDTH-1:0] rsa_product_lo ;
  bit [OUTPUT_TEXT_WIDTH-1:0] rsa_status ;
  bit [OUTPUT_TEXT_WIDTH-1:0] rsa_cycles ;
  bit [OUTPUT_TEXT_WIDTH-1:0] rsa_op_observed ;
  bit [OUTPUT_TEXT_WIDTH-1:0] rsa_key_size ;

  //Constraints for the transaction variables:

  // pragma uvmf custom class_item_additional begin
  // pragma uvmf custom class_item_additional end

  //*******************************************************************
  //*******************************************************************
  // Macros that define structs and associated functions are
  // located in RSA_out_macros.svh

  //*******************************************************************
  // Monitor macro used by RSA_out_monitor and RSA_out_monitor_bfm
  // This struct is defined in RSA_out_macros.svh
  `RSA_out_MONITOR_STRUCT
    RSA_out_monitor_s RSA_out_monitor_struct;
  //*******************************************************************
  // FUNCTION: to_monitor_struct()
  // This function packs transaction variables into a RSA_out_monitor_s
  // structure.  The function returns the handle to the RSA_out_monitor_struct.
  // This function is defined in RSA_out_macros.svh
  `RSA_out_TO_MONITOR_STRUCT_FUNCTION 
  //*******************************************************************
  // FUNCTION: from_monitor_struct()
  // This function unpacks the struct provided as an argument into transaction 
  // variables of this class.
  // This function is defined in RSA_out_macros.svh
  `RSA_out_FROM_MONITOR_STRUCT_FUNCTION 

  //*******************************************************************
  // Initiator macro used by RSA_out_driver and RSA_out_driver_bfm
  // to communicate initiator driven data to RSA_out_driver_bfm.
  // This struct is defined in RSA_out_macros.svh
  `RSA_out_INITIATOR_STRUCT
    RSA_out_initiator_s RSA_out_initiator_struct;
  //*******************************************************************
  // FUNCTION: to_initiator_struct()
  // This function packs transaction variables into a RSA_out_initiator_s
  // structure.  The function returns the handle to the RSA_out_initiator_struct.
  // This function is defined in RSA_out_macros.svh
  `RSA_out_TO_INITIATOR_STRUCT_FUNCTION  
  //*******************************************************************
  // FUNCTION: from_initiator_struct()
  // This function unpacks the struct provided as an argument into transaction 
  // variables of this class.
  // This function is defined in RSA_out_macros.svh
  `RSA_out_FROM_INITIATOR_STRUCT_FUNCTION 

  //*******************************************************************
  // Responder macro used by RSA_out_driver and RSA_out_driver_bfm
  // to communicate Responder driven data to RSA_out_driver_bfm.
  // This struct is defined in RSA_out_macros.svh
  `RSA_out_RESPONDER_STRUCT
    RSA_out_responder_s RSA_out_responder_struct;
  //*******************************************************************
  // FUNCTION: to_responder_struct()
  // This function packs transaction variables into a RSA_out_responder_s
  // structure.  The function returns the handle to the RSA_out_responder_struct.
  // This function is defined in RSA_out_macros.svh
  `RSA_out_TO_RESPONDER_STRUCT_FUNCTION 
  //*******************************************************************
  // FUNCTION: from_responder_struct()
  // This function unpacks the struct provided as an argument into transaction 
  // variables of this class.
  // This function is defined in RSA_out_macros.svh
  `RSA_out_FROM_RESPONDER_STRUCT_FUNCTION 
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
    return $sformatf("rsa_result:0x%x rsa_product_hi:0x%x rsa_product_lo:0x%x rsa_status:0x%x rsa_cycles:0x%x rsa_op_observed:0x%x rsa_key_size:0x%x",rsa_result,rsa_product_hi,rsa_product_lo,rsa_status,rsa_cycles,rsa_op_observed, rsa_key_size);
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
    RSA_out_transaction #(
        .AHB_ADDR_WIDTH(AHB_ADDR_WIDTH),
        .AHB_DATA_WIDTH(AHB_DATA_WIDTH),
        .OUTPUT_TEXT_WIDTH(OUTPUT_TEXT_WIDTH)
        )
 RHS;
    if (!$cast(RHS,rhs)) return 0;
    // pragma uvmf custom do_compare begin
    // UVMF_CHANGE_ME : Eliminate comparison of variables not to be used for compare
    // Compare only the active result width and aperture: PRODUCT for MUL,
    // RESULT for exponentiation, neither for LDMOD. Other bits may be stale.
    // Exclude status and cycles; the directed regression tracks latency.
    begin
      int unsigned kbits;
      int unsigned hi_bits;
      bit [OUTPUT_TEXT_WIDTH-1:0] mask;
      bit [OUTPUT_TEXT_WIDTH-1:0] hi_mask;
      bit                         data_ok;

      // Only one side carries the key size for a reset transaction, so take
      // whichever is populated and fall back to the full width.
      kbits = (this.rsa_key_size != 0) ? int'(this.rsa_key_size)
            : (RHS.rsa_key_size  != 0) ? int'(RHS.rsa_key_size)
            : OUTPUT_TEXT_WIDTH;
      if (kbits > OUTPUT_TEXT_WIDTH) kbits = OUTPUT_TEXT_WIDTH;
      mask = (kbits == OUTPUT_TEXT_WIDTH) ? '1
           : ((OUTPUT_TEXT_WIDTH'(1) << kbits) - 1);

      // Compare 2*kbits of product; 2048-bit keys need only the low half.
      hi_bits = (2*kbits > OUTPUT_TEXT_WIDTH) ? (2*kbits - OUTPUT_TEXT_WIDTH) : 0;
      hi_mask = (hi_bits == 0)                 ? '0
              : (hi_bits >= OUTPUT_TEXT_WIDTH) ? '1
              : ((OUTPUT_TEXT_WIDTH'(1) << hi_bits) - 1);

      case (this.rsa_op_observed[2:0])
        3'b100  : data_ok = (this.rsa_product_lo == RHS.rsa_product_lo)
                         && ((this.rsa_product_hi & hi_mask) == (RHS.rsa_product_hi & hi_mask));
        // CRT also writes RESULT; its sequence supplies validated prime factors.
        3'b010,
        3'b011,
        3'b110  : data_ok = ((this.rsa_result & mask) == (RHS.rsa_result & mask));
        default : data_ok = 1'b1;   // LDMOD / reset: no readable data
      endcase

      return (super.do_compare(rhs,comparer)
              && data_ok
              &&(this.rsa_op_observed == RHS.rsa_op_observed)
              &&(this.rsa_key_size == RHS.rsa_key_size)
              );
    end
    // pragma uvmf custom do_compare end
  endfunction

  //*******************************************************************
  // FUNCTION: do_copy()
  // This function is automatically called when the .copy() function
  // is called on this class.
  //
  virtual function void do_copy (uvm_object rhs);
    RSA_out_transaction #(
        .AHB_ADDR_WIDTH(AHB_ADDR_WIDTH),
        .AHB_DATA_WIDTH(AHB_DATA_WIDTH),
        .OUTPUT_TEXT_WIDTH(OUTPUT_TEXT_WIDTH)
        )
 RHS;
    assert($cast(RHS,rhs));
    // pragma uvmf custom do_copy begin
    super.do_copy(rhs);
    this.rsa_result = RHS.rsa_result;
    this.rsa_product_hi = RHS.rsa_product_hi;
    this.rsa_product_lo = RHS.rsa_product_lo;
    this.rsa_status = RHS.rsa_status;
    this.rsa_cycles = RHS.rsa_cycles;
    this.rsa_op_observed = RHS.rsa_op_observed;
    this.rsa_key_size = RHS.rsa_key_size;
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
      transaction_view_h = $begin_transaction(transaction_viewing_stream_h,"RSA_out_transaction",start_time);
    end
    super.add_to_wave(transaction_view_h);
    // pragma uvmf custom add_to_wave begin
    // UVMF_CHANGE_ME : Color can be applied to transaction entries based on content, example below
    // case()
    //   1 : $add_color(transaction_view_h,"red");
    //   default : $add_color(transaction_view_h,"grey");
    // endcase
    // UVMF_CHANGE_ME : Eliminate transaction variables not wanted in transaction viewing in the waveform viewer
    $add_attribute(transaction_view_h,rsa_result,"rsa_result");
    $add_attribute(transaction_view_h,rsa_product_hi,"rsa_product_hi");
    $add_attribute(transaction_view_h,rsa_product_lo,"rsa_product_lo");
    $add_attribute(transaction_view_h,rsa_status,"rsa_status");
    $add_attribute(transaction_view_h,rsa_cycles,"rsa_cycles");
    $add_attribute(transaction_view_h,rsa_op_observed,"rsa_op_observed");
    $add_attribute(transaction_view_h,rsa_key_size,"rsa_key_size");
    // pragma uvmf custom add_to_wave end
    $end_transaction(transaction_view_h,end_time);
    $free_transaction(transaction_view_h);
    `endif // QUESTA
  endfunction

endclass

// pragma uvmf custom external begin
// pragma uvmf custom external end
