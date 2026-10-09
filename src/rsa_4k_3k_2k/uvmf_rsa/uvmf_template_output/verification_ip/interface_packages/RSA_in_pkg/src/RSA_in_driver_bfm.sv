//----------------------------------------------------------------------
// Created with uvmf_gen version 2022.3
//----------------------------------------------------------------------
// pragma uvmf custom header begin
// pragma uvmf custom header end
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//     
// DESCRIPTION: 
//    This interface performs the RSA_in signal driving.  It is
//     accessed by the uvm RSA_in driver through a virtual interface
//     handle in the RSA_in configuration.  It drives the singals passed
//     in through the port connection named bus of type RSA_in_if.
//
//     Input signals from the RSA_in_if are assigned to an internal input
//     signal with a _i suffix.  The _i signal should be used for sampling.
//
//     The input signal connections are as follows:
//       bus.signal -> signal_i 
//
//     This bfm drives signals with a _o suffix.  These signals
//     are driven onto signals within RSA_in_if based on INITIATOR/RESPONDER and/or
//     ARBITRATION/GRANT status.  
//
//     The output signal connections are as follows:
//        signal_o -> bus.signal
//
//                                                                                           
//      Interface functions and tasks used by UVM components:
//
//             configure:
//                   This function gets configuration attributes from the
//                   UVM driver to set any required BFM configuration
//                   variables such as 'initiator_responder'.                                       
//                                                                                           
//             initiate_and_get_response:
//                   This task is used to perform signaling activity for initiating
//                   a protocol transfer.  The task initiates the transfer, using
//                   input data from the initiator struct.  Then the task captures
//                   response data, placing the data into the response struct.
//                   The response struct is returned to the driver class.
//
//             respond_and_wait_for_next_transfer:
//                   This task is used to complete a current transfer as a responder
//                   and then wait for the initiator to start the next transfer.
//                   The task uses data in the responder struct to drive protocol
//                   signals to complete the transfer.  The task then waits for 
//                   the next transfer.  Once the next transfer begins, data from
//                   the initiator is placed into the initiator struct and sent
//                   to the responder sequence for processing to determine 
//                   what data to respond with.
//
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//
import uvmf_base_pkg_hdl::*;
import RSA_in_pkg_hdl::*;
`include "src/RSA_in_macros.svh"

interface RSA_in_driver_bfm #(
  int AHB_ADDR_WIDTH = 32,
  int AHB_DATA_WIDTH = 32
  )

  (RSA_in_if bus);
  // The following pragma and additional ones in-lined further below are for running this BFM on Veloce
  // pragma attribute RSA_in_driver_bfm partition_interface_xif

`ifndef XRTL
// This code is to aid in debugging parameter mismatches between the BFM and its corresponding agent.
// Enable this debug by setting UVM_VERBOSITY to UVM_DEBUG
// Setting UVM_VERBOSITY to UVM_DEBUG causes all BFM's and all agents to display their parameter settings.
// All of the messages from this feature have a UVM messaging id value of "CFG"
// The transcript or run.log can be parsed to ensure BFM parameter settings match its corresponding agents parameter settings.
import uvm_pkg::*;
`include "uvm_macros.svh"
initial begin : bfm_vs_agent_parameter_debug
  `uvm_info("CFG", 
      $psprintf("The BFM at '%m' has the following parameters: AHB_ADDR_WIDTH=%x AHB_DATA_WIDTH=%x ", AHB_ADDR_WIDTH,AHB_DATA_WIDTH),
      UVM_DEBUG)
end
`endif

  // Config value to determine if this is an initiator or a responder 
  uvmf_initiator_responder_t initiator_responder;
  // Custom configuration variables.  
  // These are set using the configure function which is called during the UVM connect_phase

  tri clk_i;
  tri rst_n_i;

  // Signal list (all signals are capable of being inputs and outputs for the sake
  // of supporting both INITIATOR and RESPONDER mode operation. Expectation is that 
  // directionality in the config file was from the point-of-view of the INITIATOR

  // INITIATOR mode input signals
  tri [AHB_DATA_WIDTH-1:0] hrdata_i;
  reg [AHB_DATA_WIDTH-1:0] hrdata_o = 'bz;
  tri  hreadyout_i;
  reg  hreadyout_o = 'bz;

  // INITIATOR mode output signals
  tri  rsa_rst_n_i;
  reg  rsa_rst_n_o = 'bz;
  tri [AHB_ADDR_WIDTH-1:0] haddr_i;
  reg [AHB_ADDR_WIDTH-1:0] haddr_o = 'bz;
  tri [AHB_DATA_WIDTH-1:0] hwdata_i;
  reg [AHB_DATA_WIDTH-1:0] hwdata_o = 'bz;
  tri  hsel_i;
  reg  hsel_o = 'bz;
  tri  hwrite_i;
  reg  hwrite_o = 'bz;
  tri  hready_i;
  reg  hready_o = 'bz;
  tri [1:0] htrans_i;
  reg [1:0] htrans_o = 'bz;
  tri [2:0] hsize_i;
  reg [2:0] hsize_o = 'bz;
  tri  transaction_flag_out_monitor_i;
  reg  transaction_flag_out_monitor_o = 'bz;
  // Match the 3-bit interface encodings, including MODEXP_SEC_CRT.
  tri [2:0] test_i;
  reg [2:0] test_o = 3'bz;
  tri [2:0] op_i;
  reg [2:0] op_o = 3'bz;

  //--------------------------------------------------------------------------
  // TB-only operands for the monitor/predictor, not DUT pins. These variables
  // are driven unconditionally rather than through an INITIATOR tri-state mux.
  //--------------------------------------------------------------------------
  bit [1:0]                     keylen_o   = 2'b10;
  bit [RSA_IN_MAX_KEY_SIZE-1:0] modulus_o  = '0;
  bit [RSA_IN_MAX_KEY_SIZE-1:0] base_o     = '0;
  bit [RSA_IN_MAX_KEY_SIZE-1:0] exponent_o = '0;
  bit [31:0]                    exp_len_o  = '0;

  // Bi-directional signals
  

  assign clk_i = bus.clk;
  assign rst_n_i = bus.rst_n;

  // These are signals marked as 'input' by the config file, but the signals will be
  // driven by this BFM if put into RESPONDER mode (flipping all signal directions around)
  assign hrdata_i = bus.hrdata;
  assign bus.hrdata = (initiator_responder == RESPONDER) ? hrdata_o : 'bz;
  assign hreadyout_i = bus.hreadyout;
  assign bus.hreadyout = (initiator_responder == RESPONDER) ? hreadyout_o : 'bz;


  // These are signals marked as 'output' by the config file, but the outputs will
  // not be driven by this BFM unless placed in INITIATOR mode.
  assign bus.rsa_rst_n = (initiator_responder == INITIATOR) ? rsa_rst_n_o : 'bz;
  assign rsa_rst_n_i = bus.rsa_rst_n;
  assign bus.haddr = (initiator_responder == INITIATOR) ? haddr_o : 'bz;
  assign haddr_i = bus.haddr;
  assign bus.hwdata = (initiator_responder == INITIATOR) ? hwdata_o : 'bz;
  assign hwdata_i = bus.hwdata;
  assign bus.hsel = (initiator_responder == INITIATOR) ? hsel_o : 'bz;
  assign hsel_i = bus.hsel;
  assign bus.hwrite = (initiator_responder == INITIATOR) ? hwrite_o : 'bz;
  assign hwrite_i = bus.hwrite;
  assign bus.hready = (initiator_responder == INITIATOR) ? hready_o : 'bz;
  assign hready_i = bus.hready;
  assign bus.htrans = (initiator_responder == INITIATOR) ? htrans_o : 'bz;
  assign htrans_i = bus.htrans;
  assign bus.hsize = (initiator_responder == INITIATOR) ? hsize_o : 'bz;
  assign hsize_i = bus.hsize;
  assign bus.transaction_flag_out_monitor = (initiator_responder == INITIATOR) ? transaction_flag_out_monitor_o : 'bz;
  assign transaction_flag_out_monitor_i = bus.transaction_flag_out_monitor;
  assign bus.test = (initiator_responder == INITIATOR) ? test_o : 'bz;
  assign test_i = bus.test;
  assign bus.op = (initiator_responder == INITIATOR) ? op_o : 'bz;
  assign op_i = bus.op;
  assign bus.keylen   = keylen_o;
  assign bus.modulus  = modulus_o;
  assign bus.base     = base_o;
  assign bus.exponent = exponent_o;
  assign bus.exp_len  = exp_len_o;

  // Proxy handle to UVM driver
  RSA_in_pkg::RSA_in_driver #(
    .AHB_ADDR_WIDTH(AHB_ADDR_WIDTH),
    .AHB_DATA_WIDTH(AHB_DATA_WIDTH)
    )
  proxy;
  // pragma tbx oneway proxy.my_function_name_in_uvm_driver                 

  // ****************************************************************************
  // **************************************************************************** 
  // Macros that define structs located in RSA_in_macros.svh
  // ****************************************************************************
  // Struct for passing configuration data from RSA_in_driver to this BFM
  // ****************************************************************************
  `RSA_in_CONFIGURATION_STRUCT
  // ****************************************************************************
  // Structs for INITIATOR and RESPONDER data flow
  //*******************************************************************
  // Initiator macro used by RSA_in_driver and RSA_in_driver_bfm
  // to communicate initiator driven data to RSA_in_driver_bfm.           
  `RSA_in_INITIATOR_STRUCT
    RSA_in_initiator_s initiator_struct;
  // Responder macro used by RSA_in_driver and RSA_in_driver_bfm
  // to communicate Responder driven data to RSA_in_driver_bfm.
  `RSA_in_RESPONDER_STRUCT
    RSA_in_responder_s responder_struct;

  // ****************************************************************************
// pragma uvmf custom reset_condition_and_response begin
  // Always block used to return signals to reset value upon assertion of reset
  always @( negedge rst_n_i )
     begin
       // RESPONDER mode output signals
       hrdata_o <= 'bz;
       hreadyout_o <= 'bz;
       // INITIATOR mode output signals
       rsa_rst_n_o <= 'b0;
       haddr_o <= 'bz;
       hwdata_o <= 'bz;
       hsel_o <= 0;
       hwrite_o <= 0;
       hready_o <= 0;
       htrans_o <= 0;
       hsize_o <= 3'b011;

       transaction_flag_out_monitor_o <= '0;
       test_o <= 'bz;
       op_o <= 'bz;
       // Bi-directional signals
 
     end    
// pragma uvmf custom reset_condition_and_response end

  // pragma uvmf custom interface_item_additional begin
  // pragma uvmf custom interface_item_additional end

  //******************************************************************
  // The configure() function is used to pass agent configuration
  // variables to the driver BFM.  It is called by the driver within
  // the agent at the beginning of the simulation.  It may be called 
  // during the simulation if agent configuration variables are updated
  // and the driver BFM needs to be aware of the new configuration 
  // variables.
  //

  function void configure(RSA_in_configuration_s RSA_in_configuration_arg); // pragma tbx xtf  
    initiator_responder = RSA_in_configuration_arg.initiator_responder;
  // pragma uvmf custom configure begin
  // pragma uvmf custom configure end
  endfunction                                                                             

// pragma uvmf custom initiate_and_get_response begin
// ****************************************************************************
// UVMF_CHANGE_ME
// This task is used by an initator.  The task first initiates a transfer then
// waits for the responder to complete the transfer.
    task initiate_and_get_response( 
       // This argument passes transaction variables used by an initiator
       // to perform the initial part of a protocol transfer.  The values
       // come from a sequence item created in a sequence.
       input RSA_in_initiator_s RSA_in_initiator_struct, 
       // This argument is used to send data received from the responder
       // back to the sequence item.  The sequence item is returned to the sequence.
       output RSA_in_responder_s RSA_in_responder_struct 
       );// pragma tbx xtf  
       // 
       // Members within the RSA_in_initiator_struct:
       //   rsa_in_test_transactions test ;
       //   rsa_in_op_transactions op ;
       // Members within the RSA_in_responder_struct:
       //   rsa_in_test_transactions test ;
       //   rsa_in_op_transactions op ;
       initiator_struct = RSA_in_initiator_struct;
       //
       // Reference code;
       //    How to wait for signal value
       //      while (control_signal == 1'b1) @(posedge clk_i);
       //    
       //    How to assign a responder struct member, named xyz, from a signal.   
       //    All available initiator input and inout signals listed.
       //    Initiator input signals
       //      RSA_in_responder_struct.xyz = hrdata_i;  //    [AHB_DATA_WIDTH-1:0] 
       //      RSA_in_responder_struct.xyz = hreadyout_i;  //     
       //    Initiator inout signals
       //    How to assign a signal from an initiator struct member named xyz.   
       //    All available initiator output and inout signals listed.
       //    Notice the _o.  Those are storage variables that allow for procedural assignment.
       //    Initiator output signals
       //      rsa_rst_n_o <= RSA_in_initiator_struct.xyz;  //     
       //      haddr_o <= RSA_in_initiator_struct.xyz;  //    [AHB_ADDR_WIDTH-1:0] 
       //      hwdata_o <= RSA_in_initiator_struct.xyz;  //    [AHB_DATA_WIDTH-1:0] 
       //      hsel_o <= RSA_in_initiator_struct.xyz;  //     
       //      hwrite_o <= RSA_in_initiator_struct.xyz;  //     
       //      hready_o <= RSA_in_initiator_struct.xyz;  //     
       //      htrans_o <= RSA_in_initiator_struct.xyz;  //    [1:0] 
       //      hsize_o <= RSA_in_initiator_struct.xyz;  //    [2:0] 
       //      transaction_flag_out_monitor_o <= RSA_in_initiator_struct.xyz;  //     
       //      test_o <= RSA_in_initiator_struct.xyz;  //    [2:0] 
       //      op_o <= RSA_in_initiator_struct.xyz;  //    [2:0] 
       //    Initiator inout signals
    // Initiate a transfer using the data received.
    @(posedge clk_i);
    /*
    $display("** RSA_in_driver_bfm** : Inside initiate_and_get_response");
    $display("** RSA_in_driver_bfm** : test = %0s", RSA_in_initiator_struct.test.name());
    $display("** RSA_in_driver_bfm** : op = %0s", RSA_in_initiator_struct.op.name());
      */
    // Publish operands and select the width before driving this transaction.
    // set_key_size updates local state; subsequent commands carry the width.
    keylen_o   = RSA_in_initiator_struct.keylen;
    modulus_o  = RSA_in_initiator_struct.modulus;
    base_o     = RSA_in_initiator_struct.base;
    exponent_o = RSA_in_initiator_struct.exponent;
    exp_len_o  = RSA_in_initiator_struct.exp_len;
    set_key_size(rsa_keylen_bits(RSA_in_initiator_struct.keylen));

    case (RSA_in_initiator_struct.test)
      rsa_reset_test      : rsa_init(RSA_in_initiator_struct.test, RSA_in_initiator_struct.op);
      rsa_normal_test     : rsa_test(RSA_in_initiator_struct.test, RSA_in_initiator_struct.op);
      rsa_otf_reset_test  : rsa_test(RSA_in_initiator_struct.test, RSA_in_initiator_struct.op);
      rsa_kat_test        : rsa_test(RSA_in_initiator_struct.test, RSA_in_initiator_struct.op);
      // Refusals must not pulse the output activity flag: the predictor emits
      // no expectation, so normal dispatch would misalign the scoreboard.
      rsa_err_test        : rsa_err_test_run(RSA_in_initiator_struct.test, RSA_in_initiator_struct.op);
      default             : rsa_test(RSA_in_initiator_struct.test, RSA_in_initiator_struct.op);
    endcase

  endtask   

  //==========================================================================
  // RSA register driver; keep addressing and bus timing aligned with rsa_top_tb.
  //==========================================================================

  //--------------------------------------------------------------------------
  // Register map (rsa_top_tb.sv:62-77)
  //--------------------------------------------------------------------------
  parameter BASE_ADDR         = 32'h0000_0000;
  parameter ADDR_NAME0        = BASE_ADDR + 32'h0000_0000;
  parameter ADDR_VERSION      = BASE_ADDR + 32'h0000_0008;
  parameter ADDR_CTRL         = BASE_ADDR + 32'h0000_0010;
  parameter ADDR_STATUS       = BASE_ADDR + 32'h0000_0018;
  parameter ADDR_CONFIG       = BASE_ADDR + 32'h0000_001C;
  parameter ADDR_MODULUS      = BASE_ADDR + 32'h0000_0400;
  parameter ADDR_A            = BASE_ADDR + 32'h0000_0600;
  parameter ADDR_B            = BASE_ADDR + 32'h0000_0800;
  parameter ADDR_E            = BASE_ADDR + 32'h0000_0A00;
  parameter ADDR_D            = BASE_ADDR + 32'h0000_0C00;
  parameter ADDR_RESULT       = BASE_ADDR + 32'h0000_1000;
  parameter ADDR_PRODUCT      = BASE_ADDR + 32'h0000_1200;
  parameter ADDR_P            = BASE_ADDR + 32'h0000_1600;
  parameter ADDR_Q            = BASE_ADDR + 32'h0000_1700;
  parameter ADDR_QINV         = BASE_ADDR + 32'h0000_1E00;

  // Aperture sizes in 32-bit registers (rsa_top_tb.sv:54-60,80).
  parameter MOD_REGS  = 128;
  parameter A_REGS    = 128;
  parameter B_REGS    = 128;
  parameter E_REGS    = 4;
  parameter D_REGS    = 132;
  parameter RES_REGS  = 128;
  parameter PROD_REGS = 256;
  parameter CRT_REGS  = 64;
  parameter ADDR_DP           = BASE_ADDR + 32'h0000_1C00;
  parameter ADDR_DQ           = BASE_ADDR + 32'h0000_1D00;

  // STATUS layout: READY[0] VALID[1] ERROR[17:2].
  parameter STATUS_READY_BIT = 0;
  parameter STATUS_ERR_LSB   = 2;
  parameter STATUS_ERR_MSB   = 17;

  // tessera_rsa_ctrl ERR_* indices relative to STATUS_ERR_LSB, not absolute STATUS bits.
  parameter ERR_IDX_BAD_CMD     = 0;
  parameter ERR_IDX_NO_CONTEXT  = 1;
  parameter ERR_IDX_BAD_MOD     = 2;
  parameter ERR_IDX_BAD_BASE    = 3;
  parameter ERR_IDX_CRT_UNAVAIL = 4;
  parameter ERR_IDX_MOD_RANGE   = 5;
  parameter ERR_IDX_BAD_EXP_LEN = 6;
  parameter ERR_IDX_CRT_FAIL    = 7;
  parameter ERR_IDX_BAD_KEYLEN  = 8;
  parameter ERR_IDX_MOD_FIT     = 9;
  // Separate selector for ERR_BAD_KEYLEN's context-mismatch rung, outside
  // the error-index range; unsupported encoding needs independent stimulus.
  parameter ERR_IDX_KEYLEN_MISMATCH = 16;
  parameter STATUS_VALID_BIT = 1;

  parameter AHB_HTRANS_IDLE   = 2'b00;
  parameter AHB_HTRANS_BUSY   = 2'b01;
  parameter AHB_HTRANS_NONSEQ = 2'b10;
  parameter AHB_HTRANS_SEQ    = 2'b11;

  // Widest operand the environment supports.  The PRODUCT aperture returned by
  // MUL is twice the key size, hence the separate width.
  parameter MAX_KEY_SIZE  = 4096;
  parameter MAX_PROD_SIZE = 8192;

  // Exponent apertures are sized KEY_SIZE+64 in the directed TB; carry the same
  // headroom so a D write of EXP_WORDS words cannot overflow the vector.
  parameter MAX_EXP_SIZE  = MAX_KEY_SIZE + 64;

  reg [31:0] cycle_ctr;
  reg [7:0]  test_case_num;

  // Sequence-selected runtime width for this transaction.
  int unsigned cur_key_size  = MAX_KEY_SIZE;
  int unsigned cur_key_words = MAX_KEY_SIZE/32;

  //--------------------------------------------------------------------------
  // Minimal AHB-Lite master: one non-sequential beat per access.
  // Cycle-for-cycle identical to rsa_top_tb.sv:194-222 -- do not "improve" the
  // timing here without changing the directed TB in lockstep.
  //--------------------------------------------------------------------------
  task automatic ahb_write(input [31:0] addr, input [31:0] data);
    @(posedge clk_i);
    hsel_o   <= 1'b1;
    hwrite_o <= 1'b1;
    htrans_o <= AHB_HTRANS_NONSEQ;
    hsize_o  <= 3'b010;
    haddr_o  <= addr;
    hready_o <= 1'b1;
    @(posedge clk_i);
    htrans_o <= AHB_HTRANS_IDLE;
    hwdata_o <= data;
    @(posedge clk_i);
    hsel_o   <= 1'b0;
    hwrite_o <= 1'b0;
  endtask

  task automatic ahb_read(input [31:0] addr, output [31:0] data);
    @(posedge clk_i);
    hsel_o   <= 1'b1;
    hwrite_o <= 1'b0;
    htrans_o <= AHB_HTRANS_NONSEQ;
    hsize_o  <= 3'b010;
    haddr_o  <= addr;
    hready_o <= 1'b1;
    @(posedge clk_i);
    htrans_o <= AHB_HTRANS_IDLE;
    @(posedge clk_i);
    hsel_o   <= 1'b0;
    data = hrdata_i;
  endtask

  //--------------------------------------------------------------------------
  // Big-endian, right-aligned operands: word 0 is most significant;
  // shortened keys occupy higher register indices.
  //--------------------------------------------------------------------------
  // Write full apertures: stale upper words can fail mod_fits/mul_fits,
  // reject LDMOD, and leave subsequent MODEXP without a context.
  task automatic write_wide(input [31:0] base_addr, input int unsigned n_regs,
                            input int unsigned n_words,
                            input [MAX_EXP_SIZE-1:0] value);
    for (int w = 0; w < n_words; w++) begin
      ahb_write(base_addr + 32'(4*(n_regs - n_words + w)),
                value[(n_words-1-w)*32 +: 32]);
    end
  endtask

  task automatic read_result(output [MAX_KEY_SIZE-1:0] value);
    reg [31:0] rd;
    value = '0;
    for (int w = 0; w < cur_key_words; w++) begin
      ahb_read(ADDR_RESULT + 32'(4*(RES_REGS - cur_key_words + w)), rd);
      value[(cur_key_words-1-w)*32 +: 32] = rd;
    end
  endtask

  task automatic read_product(output [MAX_PROD_SIZE-1:0] value);
    reg [31:0] rd;
    value = '0;
    for (int w = 0; w < 2*cur_key_words; w++) begin
      ahb_read(ADDR_PRODUCT + 32'(4*(PROD_REGS - 2*cur_key_words + w)), rd);
      value[(2*cur_key_words-1-w)*32 +: 32] = rd;
    end
  endtask

  //--------------------------------------------------------------------------
  // Handshake / command helpers
  //--------------------------------------------------------------------------
  task automatic wait_ready(output int unsigned cycles);
    reg [31:0] st;
    int unsigned t0;
    t0 = cycle_ctr;
    forever begin
      ahb_read(ADDR_STATUS, st);
      if (st[STATUS_READY_BIT]) break;
    end
    cycles = cycle_ctr - t0;
    // Report refusals before stale RESULT causes a later mismatch.
    // Keep expected-refusal diagnostics free of "ERROR": the regression parser
    // treats that word as failure. Genuine failures use flag_error()/UVM_ERROR.
    if (|st[STATUS_ERR_MSB:STATUS_ERR_LSB])
      $display("%0t RSA: *** COMMAND REFUSED, STATUS=%08x (ERR_FIELD %0d)",
               $time, st, st[STATUS_ERR_MSB:STATUS_ERR_LSB]);
  endtask

  task automatic get_status(output [31:0] st);
    ahb_read(ADDR_STATUS, st);
  endtask

  // CTRL[3:0] opcode with bit 3 as the CRT modifier, MUL on bit 4, ZEROIZE on
  // bit 5.  Translate here so the stimulus keeps the internal opcode names.

  reg [1:0] cfg_shorten = 2'b00;
  // Translate internal shortening steps to absolute CTRL.KEY_LEN encoding;
  // unsupported widths map to the reserved ERR_BAD_KEYLEN case.
  function automatic reg [1:0] keylen_code(input reg [1:0] sh);
    int unsigned bits;
    bits = MAX_KEY_SIZE - 1024 * int'(sh);
    case (bits)
      2048:    keylen_code = 2'b00;
      3072:    keylen_code = 2'b01;
      4096:    keylen_code = 2'b10;
      default: keylen_code = 2'b11;
    endcase
  endfunction

  task automatic issue_cmd(input [2:0] cmd);
    reg [31:0] ctrl_word;
    ctrl_word = 32'h0;
    case (cmd)
      3'b100:  ctrl_word[4]   = 1'b1;      // CMD_MUL
      3'b110:  ctrl_word[3:0] = 4'b1011;   // CMD_MODEXP_SEC_CRT
      default: ctrl_word[3:0] = {1'b0, cmd};
    endcase
    ctrl_word[6:5] = keylen_code(cfg_shorten);
    ahb_write(ADDR_CTRL, ctrl_word);
  endtask

  // CONFIG is read-only; issue_cmd carries the selected width in CTRL.KEY_LEN.


  // Internal shortening counts 1024-bit steps below the native width:
  //     keylen_geom = GEOM_FULL - GEOM_STEP * keylen_shorten_eff
  // Select it before LDMOD builds the width-dependent Montgomery context.
  task automatic set_key_size(input int unsigned key_size);
    cur_key_size  = key_size;
    cur_key_words = key_size/32;
    cfg_shorten   = 2'((MAX_KEY_SIZE - key_size)/1024);
  endtask

  //--------------------------------------------------------------------------
  // Operations.  One task per CTRL.CMD encoding.
  //--------------------------------------------------------------------------

  // LDMOD builds the Montgomery context at the selected runtime width.
  task automatic do_ldmod(input [MAX_KEY_SIZE-1:0] n, output int unsigned cycles);
    write_wide(ADDR_MODULUS, MOD_REGS, MOD_REGS, MAX_EXP_SIZE'(n));
    issue_cmd(3'b001);                       // CMD_LDMOD
    wait_ready(cycles);
  endtask

  // MODEXP_PUB uses the E aperture (4 regs); MODEXP_SEC and the CRT form use
  // the wider D aperture.
  task automatic do_modexp(input [2:0] cmd,
                           input [MAX_KEY_SIZE-1:0] base,
                           input [MAX_KEY_SIZE-1:0] exp,
                           input int unsigned exp_len,
                           output [MAX_KEY_SIZE-1:0] res,
                           output int unsigned cycles);
    write_wide(ADDR_A, A_REGS, A_REGS, MAX_EXP_SIZE'(base));
    if (cmd == 3'b010) write_wide(ADDR_E, E_REGS, E_REGS, MAX_EXP_SIZE'(exp));
    else               write_wide(ADDR_D, D_REGS, D_REGS,
                                  MAX_EXP_SIZE'(exp));
    issue_cmd(cmd);
    wait_ready(cycles);
    read_result(res);
  endtask

  // MUL needs no LDMOD, but must carry its own selected width. Operand fit is:
  //     mul_fits_s[gs] = (base_in[KEY_SIZE-1:EW] == '0)
  //                   && (mul_b_in[KEY_SIZE-1:EW] == '0)     (tessera_rsa_ctrl.sv:611)
  // A narrower width rejects operands; a wider one can hide a wrong-width schedule.
  task automatic do_mul(input [MAX_KEY_SIZE-1:0] a, input [MAX_KEY_SIZE-1:0] b,
                        output [MAX_PROD_SIZE-1:0] prod,
                        output int unsigned cycles);
    write_wide(ADDR_A, A_REGS, A_REGS, MAX_EXP_SIZE'(a));
    write_wide(ADDR_B, B_REGS, B_REGS, MAX_EXP_SIZE'(b));
    issue_cmd(3'b100);                       // CMD_MUL
    wait_ready(cycles);
    read_product(prod);
  endtask

  //--------------------------------------------------------------------------
  // Load all five write-only CRT apertures before LDMOD arms the p/q contexts.
  // tessera_rsa_ctrl reads them continuously; the CRT command does not latch the key.
  // CRT fields occupy half the runtime key width; write full apertures.
  //--------------------------------------------------------------------------
  task automatic load_crt_key();
    write_wide(ADDR_P,    CRT_REGS, CRT_REGS, MAX_EXP_SIZE'(initiator_struct.p));
    write_wide(ADDR_Q,    CRT_REGS, CRT_REGS, MAX_EXP_SIZE'(initiator_struct.q));
    write_wide(ADDR_DP,   CRT_REGS, CRT_REGS, MAX_EXP_SIZE'(initiator_struct.dp));
    write_wide(ADDR_DQ,   CRT_REGS, CRT_REGS, MAX_EXP_SIZE'(initiator_struct.dq));
    write_wide(ADDR_QINV, CRT_REGS, CRT_REGS, MAX_EXP_SIZE'(initiator_struct.qinv));
  endtask

  //--------------------------------------------------------------------------
  // Reset
  //--------------------------------------------------------------------------
  task do_assert_rst();
    begin
      rsa_rst_n_o = 0;
      transaction_flag_out_monitor_o = 0;
      repeat (5) @(posedge clk_i);
      rsa_rst_n_o = 1;
    end
  endtask

  task rsa_init (
    input rsa_in_test_transactions test,
    input rsa_in_op_transactions op
    );

    $display("%0t ***************   RSA: starting reset", $time);
    test_o = test;
    op_o   = op;
    rsa_rst_n_o <= 1'b0;
    transaction_flag_out_monitor_o = 0;
    cycle_ctr     = '0;
    test_case_num = '0;
    cfg_shorten   = 2'b00;

    haddr_o  = 'Z;
    hwdata_o = 'Z;
    hsel_o   = 0;
    hwrite_o = 0;
    hready_o = 0;
    htrans_o = AHB_HTRANS_IDLE;
    hsize_o  = 3'b010;

    repeat (10) @(posedge clk_i);
    rsa_rst_n_o <= 1'b1;
    repeat (5) @(posedge clk_i);
    // Leave the flag low: a later falling edge would publish an unmatched result.
    transaction_flag_out_monitor_o = 0;

    $display("%0t ***************   RSA: reset complete", $time);
  endtask

  //--------------------------------------------------------------------------
  // Check bus wiring through ID reads before running long exponentiations.
  //--------------------------------------------------------------------------
  task automatic check_id();
    reg [31:0] rd;
    ahb_read(ADDR_NAME0, rd);
    $display("%0t RSA: NAME0   = %h", $time, rd);
    ahb_read(ADDR_VERSION, rd);
    $display("%0t RSA: VERSION = %h", $time, rd);
  endtask

  //--------------------------------------------------------------------------
  // Self-check MUL locally; modular results use the predictor and scoreboard.
  //--------------------------------------------------------------------------
  //--------------------------------------------------------------------------
  // Propagate BFM self-check failures through the proxy as UVM_ERROR.
  //--------------------------------------------------------------------------
  function automatic void flag_error(input string msg);
    $display("%0t RSA ERROR: %s", $time, msg);
    if (proxy != null) proxy.report_bfm_error(msg);
  endfunction

  task automatic rsa_mul_test();
    reg [MAX_PROD_SIZE-1:0] prod, expected;
    reg [31:0]              st;
    int unsigned cycles;

    // MUL reuses the transaction's base/exponent fields as its two factors.
    do_mul(initiator_struct.base, initiator_struct.exponent, prod, cycles);

    // Reject refusals explicitly before comparing a possibly stale PRODUCT.
    get_status(st);
    if (st[1] !== 1'b1)
      flag_error($sformatf("MUL did not set VALID (STATUS = %h) at key_size %0d",
                           st, cur_key_size));

    expected = MAX_PROD_SIZE'(initiator_struct.base)
             * MAX_PROD_SIZE'(initiator_struct.exponent);
    if (prod !== expected) begin
      flag_error($sformatf("MUL mismatch at key_size %0d", cur_key_size));
      $display("           got      = %h", prod[2*cur_key_size-1 -: 256]);
      $display("           expected = %h", expected[2*cur_key_size-1 -: 256]);
    end
    else begin
      $display("%0t RSA: MUL passed at key_size %0d (%0d cycles)",
               $time, cur_key_size, cycles);
    end
  endtask

  task automatic rsa_ldmod_test();
    int unsigned cycles;
    do_ldmod(initiator_struct.modulus, cycles);
    $display("%0t RSA: LDMOD completed at key_size %0d (%0d cycles)",
             $time, cur_key_size, cycles);
  endtask

  // Load the modulus per exponentiation so randomized transactions are independent.
  task automatic rsa_modexp_test(input [2:0] cmd);
    reg [MAX_KEY_SIZE-1:0] res;
    int unsigned ld_cycles, cycles;

    do_ldmod(initiator_struct.modulus, ld_cycles);
    do_modexp(cmd, initiator_struct.base, initiator_struct.exponent,
              initiator_struct.exp_len, res, cycles);

    $display("%0t RSA: %s completed at key_size %0d (%0d cycles)", $time,
             (cmd == 3'b010) ? "MODEXP_PUB" : "MODEXP_SEC", cur_key_size, cycles);
  endtask

  //--------------------------------------------------------------------------
  // MODEXP_SEC_CRT uses dp/dq/qinv, not D. Load public e in E for the
  // Bellcore check, which re-encrypts the result and compares it with the base.
  //--------------------------------------------------------------------------
  task automatic rsa_crt_test();
    reg [MAX_KEY_SIZE-1:0] res;
    reg [31:0]             st;
    int unsigned ld_cycles, cycles;

    load_crt_key();
    do_ldmod(initiator_struct.modulus, ld_cycles);
    $display("%0t RSA: CRT_LDMOD completed at key_size %0d (%0d cycles)",
             $time, cur_key_size, ld_cycles);

    write_wide(ADDR_A, A_REGS, A_REGS, MAX_EXP_SIZE'(initiator_struct.base));
    write_wide(ADDR_E, E_REGS, E_REGS, MAX_EXP_SIZE'(32'h0001_0001));
    issue_cmd(3'b110);
    wait_ready(cycles);

    get_status(st);
    if (st[1] !== 1'b1)
      flag_error($sformatf("MODEXP_SEC_CRT did not set VALID (STATUS = %h)", st));

    read_result(res);
    $display("%0t RSA: MODEXP_SEC_CRT completed at key_size %0d (%0d cycles)",
             $time, cur_key_size, cycles);
  endtask

  //--------------------------------------------------------------------------
  // Deliberate refusals: the first failing precondition sets one cmd_error bit.
  // Isolate each target rung by satisfying earlier checks, building context
  // where needed. Check the exact index to detect priority masking.
  // Do not pulse output activity: RESULT stays stale and the predictor skips it.
  //--------------------------------------------------------------------------

  // Expect STATUS.READY with exactly the named ERROR index set.
  task automatic expect_error(input string what, input int unsigned idx);
    reg [31:0] st;
    get_status(st);
    if (!st[STATUS_READY_BIT]) begin
      flag_error($sformatf("%s: DUT never returned to READY (STATUS=%08x)", what, st));
    end
    else if (st[STATUS_ERR_LSB + idx] !== 1'b1) begin
      // Acceptance or a different refusal both fail the targeted precondition check.
      flag_error($sformatf("%s: expected ERROR[%0d], got STATUS=%08x (ERROR field %0d)",
                           what, idx, st, st[STATUS_ERR_MSB:STATUS_ERR_LSB]));
    end
    else begin
      $display("%0t RSA: refusal OK -- %s -> ERR_IDX %0d (STATUS=%08x)",
               $time, what, idx, st);
    end
  endtask

  // Poll to READY without logging an expected refusal as an unexpected event.
  task automatic issue_and_settle(input [2:0] cmd);
    int unsigned cycles;
    issue_cmd(cmd);
    wait_ready(cycles);
  endtask

  // Build a known-good full-width context so a later recipe can violate one
  // precondition with everything before it satisfied.
  task automatic build_good_context(output [MAX_KEY_SIZE-1:0] n);
    int unsigned cycles;
    n = '0;
    for (int w = 0; w < cur_key_words; w++) n[w*32 +: 32] = $urandom();
    n[0]                = 1'b1;              // odd: Montgomery needs gcd(n,2)=1
    n[cur_key_size-1]   = 1'b1;              // occupies the declared width
    n[cur_key_size-1 -: 64] = {1'b1, 63'h0}; // top RADIX word not all-ones, so
                                             // mod_in_range holds
    do_ldmod(n, cycles);
  endtask

  task automatic rsa_err_test_run (
    input rsa_in_test_transactions test,
    input rsa_in_op_transactions op
    );

    reg [MAX_KEY_SIZE-1:0] n;
    reg [MAX_KEY_SIZE-1:0] small_n;
    reg [MAX_KEY_SIZE-1:0] bad_n;
    int unsigned           cycles;
    reg [1:0]              saved_shorten;

    test_o = test;
    op_o   = op;
    transaction_flag_out_monitor_o = 0;

    case (initiator_struct.err_case)

      // ERR_BAD_CMD: reserved opcode, requiring no operand setup.
      ERR_IDX_BAD_CMD: begin
        issue_and_settle(3'b111);
        expect_error("reserved CTRL opcode 3'b111", ERR_IDX_BAD_CMD);
      end

      // ERR_NO_CONTEXT: reset must invalidate context before MODEXP without LDMOD.
      ERR_IDX_NO_CONTEXT: begin
        do_assert_rst();
        cfg_shorten = 2'((MAX_KEY_SIZE - cur_key_size)/1024);
        write_wide(ADDR_A, A_REGS, A_REGS, MAX_EXP_SIZE'(initiator_struct.base));
        write_wide(ADDR_E, E_REGS, E_REGS, MAX_EXP_SIZE'(32'h0001_0001));
        issue_and_settle(3'b010);            // CMD_MODEXP_PUB
        expect_error("MODEXP_PUB after reset with no LDMOD", ERR_IDX_NO_CONTEXT);
      end

      // ERR_BAD_MOD: an even modulus has no Montgomery inverse.
      ERR_IDX_BAD_MOD: begin
        bad_n = '0;
        for (int w = 0; w < cur_key_words; w++) bad_n[w*32 +: 32] = $urandom();
        bad_n[0]              = 1'b0;        // <-- the violation
        bad_n[cur_key_size-1] = 1'b1;
        write_wide(ADDR_MODULUS, MOD_REGS, MOD_REGS, MAX_EXP_SIZE'(bad_n));
        issue_and_settle(3'b001);            // CMD_LDMOD
        expect_error("LDMOD with an even modulus", ERR_IDX_BAD_MOD);
      end

      // ERR_MOD_FIT: shortened moduli must fill the selected width with zero
      // upper bits. The native-width check is bypassed:
      //   if (gs == 0) assign mod_fits_s[gs] = 1'b1;
      // Use shortening 1 to reach this rung independently of the current width.
      ERR_IDX_MOD_FIT: begin
        saved_shorten = cfg_shorten;
        cfg_shorten   = 2'd1;
        small_n = '0;
        small_n[63:0] = 64'hDEAD_BEEF_0000_0003;   // odd, > 2, but tiny
        write_wide(ADDR_MODULUS, MOD_REGS, MOD_REGS, MAX_EXP_SIZE'(small_n));
        issue_and_settle(3'b001);
        expect_error("LDMOD with a modulus far below the declared width",
                     ERR_IDX_MOD_FIT);
        cfg_shorten = saved_shorten;
      end

      // ERR_MOD_RANGE: all-one top RADIX bits risk final-subtraction overflow.
      // Still fill the selected width to pass the earlier mod_fits check.
      ERR_IDX_MOD_RANGE: begin
        bad_n = '0;
        for (int w = 0; w < cur_key_words; w++) bad_n[w*32 +: 32] = $urandom();
        bad_n[0] = 1'b1;
        bad_n[cur_key_size-1 -: 64] = {64{1'b1}};  // <-- the violation
        write_wide(ADDR_MODULUS, MOD_REGS, MOD_REGS, MAX_EXP_SIZE'(bad_n));
        issue_and_settle(3'b001);
        expect_error("LDMOD with the top RADIX word all ones", ERR_IDX_MOD_RANGE);
      end

      // ERR_BAD_BASE: exceed the selected width, possible only when shortened.
      // A fitting base >= n is legal: the top-bit-set modulus bounds base < 2n.
      ERR_IDX_BAD_BASE: begin
        if (cur_key_size == MAX_KEY_SIZE) begin
          `uvm_info("ERRINJ", "ERR_BAD_BASE not reachable at the full built width -- skipped", UVM_LOW)
        end
        else begin
          build_good_context(n);
          bad_n = MAX_EXP_SIZE'(n);
          bad_n[cur_key_size] = 1'b1;              // <-- one bit too wide
          write_wide(ADDR_A, A_REGS, A_REGS, bad_n);
          write_wide(ADDR_E, E_REGS, E_REGS, MAX_EXP_SIZE'(32'h0001_0001));
          issue_and_settle(3'b010);
          expect_error("MODEXP_PUB with a base wider than the declared key length",
                       ERR_IDX_BAD_BASE);
        end
      end


      // ERR_BAD_KEYLEN: unsupported encoding, distinct from context mismatch.
      ERR_IDX_BAD_KEYLEN: begin
        saved_shorten = cfg_shorten;
        // keylen_code() maps a shortening the build cannot express onto the
        // reserved CTRL.KEY_LEN encoding 2'b11, which is refused at every build.
        cfg_shorten   = 2'b11;               // <-- the violation
        write_wide(ADDR_MODULUS, MOD_REGS, MOD_REGS,
                   MAX_EXP_SIZE'(initiator_struct.modulus));
        issue_and_settle(3'b001);
        expect_error("LDMOD with the reserved CTRL.KEY_LEN encoding", ERR_IDX_BAD_KEYLEN);
        cfg_shorten = saved_shorten;
      end

      // ERR_BAD_KEYLEN: Montgomery context is width-dependent.
      // Build at this transaction's width, then request one step narrower.
      ERR_IDX_KEYLEN_MISMATCH: begin
        build_good_context(n);
        cfg_shorten = cfg_shorten + 2'd1;    // <-- run narrower than the context
        write_wide(ADDR_A, A_REGS, A_REGS, MAX_EXP_SIZE'(initiator_struct.base));
        write_wide(ADDR_E, E_REGS, E_REGS, MAX_EXP_SIZE'(32'h0001_0001));
        issue_and_settle(3'b010);
        expect_error("MODEXP_PUB at a width the context was not built for",
                     ERR_IDX_BAD_KEYLEN);
        cfg_shorten = cfg_shorten - 2'd1;
      end

      // ERR_CRT_UNAVAIL requires a non-CRT build; CRT must not silently fall back.
      ERR_IDX_CRT_UNAVAIL: begin
        build_good_context(n);
        write_wide(ADDR_A, A_REGS, A_REGS, MAX_EXP_SIZE'(initiator_struct.base));
        write_wide(ADDR_E, E_REGS, E_REGS, MAX_EXP_SIZE'(32'h0001_0001));
        issue_and_settle(3'b110);            // CMD_MODEXP_SEC_CRT
        expect_error("MODEXP_SEC_CRT on an instance without the CRT datapath",
                     ERR_IDX_CRT_UNAVAIL);
      end

      // ERR_CRT_FAIL: crt_key_ok requires
      //   p[0] && q[0] && p_top_bit && q_top_bit && pq_above_lane_clear
      //   && (qinv < p)
      //
      // Arm CRT with valid material before corrupting qinv; earlier corruption
      // prevents context arming and hits ERR_NO_CONTEXT instead.
      // CRT apertures are read continuously, so qinv := p isolates the qinv < p
      // failure while preserving the armed context and other key checks.
      ERR_IDX_CRT_FAIL: begin
        load_crt_key();
        do_ldmod(initiator_struct.modulus, cycles);
        write_wide(ADDR_QINV, CRT_REGS, CRT_REGS,
                   MAX_EXP_SIZE'(initiator_struct.p));
        write_wide(ADDR_A, A_REGS, A_REGS, MAX_EXP_SIZE'(initiator_struct.base));
        write_wide(ADDR_E, E_REGS, E_REGS, MAX_EXP_SIZE'(32'h0001_0001));
        issue_and_settle(3'b110);
        expect_error("MODEXP_SEC_CRT with qinv >= p broken after LDMOD",
                     ERR_IDX_CRT_FAIL);
      end

      default: begin
        flag_error($sformatf("rsa_err_test: unknown err_case %0d",
                             initiator_struct.err_case));
      end
    endcase

    test_case_num = test_case_num + 1;
  endtask

  //--------------------------------------------------------------------------
  // Top-level dispatch.
  //--------------------------------------------------------------------------
  task automatic rsa_test (
    input rsa_in_test_transactions test,
    input rsa_in_op_transactions op
    );

    test_o = test;
    op_o   = op;
    transaction_flag_out_monitor_o = 0;

    // Complete an operation after on-the-fly reset to check DUT recovery.
    if (test == rsa_otf_reset_test) do_assert_rst();

    check_id();

    case (op)
      rsa_op_mul            : rsa_mul_test();
      rsa_op_ldmod          : rsa_ldmod_test();
      rsa_op_modexp_pub     : rsa_modexp_test(3'b010);
      rsa_op_modexp_sec     : rsa_modexp_test(3'b011);
      rsa_op_modexp_sec_crt : rsa_crt_test();
      default               : rsa_mul_test();
    endcase

    test_case_num = test_case_num + 1;
    transaction_flag_out_monitor_o = 1;
    @(posedge clk_i);
    transaction_flag_out_monitor_o = 0;
  endtask

  // Match the directed TB's free-running counter for comparable command latency.
  always @(posedge clk_i) begin
    if (!rst_n_i) cycle_ctr <= '0;
    else          cycle_ctr <= cycle_ctr + 1;
  end

// pragma uvmf custom initiate_and_get_response end

// pragma uvmf custom respond_and_wait_for_next_transfer begin
// ****************************************************************************
// The first_transfer variable is used to prevent completing a transfer in the 
// first call to this task.  For the first call to this task, there is not
// current transfer to complete.
bit first_transfer=1;

// UVMF_CHANGE_ME
// This task is used by a responder.  The task first completes the current 
// transfer in progress then waits for the initiator to start the next transfer.
  task respond_and_wait_for_next_transfer( 
       // This argument is used to send data received from the initiator
       // back to the sequence item.  The sequence determines how to respond.
       output RSA_in_initiator_s RSA_in_initiator_struct, 
       // This argument passes transaction variables used by a responder
       // to complete a protocol transfer.  The values come from a sequence item.       
       input RSA_in_responder_s RSA_in_responder_struct 
       );// pragma tbx xtf   
  // Variables within the RSA_in_initiator_struct:
  //   rsa_in_test_transactions test ;
  //   rsa_in_op_transactions op ;
  // Variables within the RSA_in_responder_struct:
  //   rsa_in_test_transactions test ;
  //   rsa_in_op_transactions op ;
       // Reference code;
       //    How to wait for signal value
       //      while (control_signal == 1'b1) @(posedge clk_i);
       //    
       //    How to assign a responder struct member, named xyz, from a signal.   
       //    All available responder input and inout signals listed.
       //    Responder input signals
       //      RSA_in_responder_struct.xyz = rsa_rst_n_i;  //     
       //      RSA_in_responder_struct.xyz = haddr_i;  //    [AHB_ADDR_WIDTH-1:0] 
       //      RSA_in_responder_struct.xyz = hwdata_i;  //    [AHB_DATA_WIDTH-1:0] 
       //      RSA_in_responder_struct.xyz = hsel_i;  //     
       //      RSA_in_responder_struct.xyz = hwrite_i;  //     
       //      RSA_in_responder_struct.xyz = hready_i;  //     
       //      RSA_in_responder_struct.xyz = htrans_i;  //    [1:0] 
       //      RSA_in_responder_struct.xyz = hsize_i;  //    [2:0] 
       //      RSA_in_responder_struct.xyz = transaction_flag_out_monitor_i;  //     
       //      RSA_in_responder_struct.xyz = test_i;  //    [2:0] 
       //      RSA_in_responder_struct.xyz = op_i;  //    [1:0] 
       //    Responder inout signals
       //    How to assign a signal, named xyz, from an initiator struct member.   
       //    All available responder output and inout signals listed.
       //    Notice the _o.  Those are storage variables that allow for procedural assignment.
       //    Responder output signals
       //      hrdata_o <= RSA_in_initiator_struct.xyz;  //    [AHB_DATA_WIDTH-1:0] 
       //      hreadyout_o <= RSA_in_initiator_struct.xyz;  //     
       //    Responder inout signals
    
  @(posedge clk_i);
  if (!first_transfer) begin
    // Perform transfer response here.   
    // Reply using data recieved in the RSA_in_responder_struct.
    @(posedge clk_i);
    // Reply using data recieved in the transaction handle.
    @(posedge clk_i);
  end
    // Wait for next transfer then gather info from intiator about the transfer.
    // Place the data into the RSA_in_initiator_struct.
    @(posedge clk_i);
    @(posedge clk_i);
    first_transfer = 0;
  endtask
// pragma uvmf custom respond_and_wait_for_next_transfer end

 
endinterface

// pragma uvmf custom external begin
// pragma uvmf custom external end
