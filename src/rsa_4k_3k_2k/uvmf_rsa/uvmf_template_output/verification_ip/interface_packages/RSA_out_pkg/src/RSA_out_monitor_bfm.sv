//----------------------------------------------------------------------
// Created with uvmf_gen version 2022.3
//----------------------------------------------------------------------
// pragma uvmf custom header begin
// pragma uvmf custom header end
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//     
// DESCRIPTION: This interface performs the RSA_out signal monitoring.
//      It is accessed by the uvm RSA_out monitor through a virtual
//      interface handle in the RSA_out configuration.  It monitors the
//      signals passed in through the port connection named bus of
//      type RSA_out_if.
//
//     Input signals from the RSA_out_if are assigned to an internal input
//     signal with a _i suffix.  The _i signal should be used for sampling.
//
//     The input signal connections are as follows:
//       bus.signal -> signal_i 
//
//      Interface functions and tasks used by UVM components:
//             monitor(inout TRANS_T txn);
//                   This task receives the transaction, txn, from the
//                   UVM monitor and then populates variables in txn
//                   from values observed on bus activity.  This task
//                   blocks until an operation on the RSA_out bus is complete.
//
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//
import uvmf_base_pkg_hdl::*;
import RSA_out_pkg_hdl::*;
`include "src/RSA_out_macros.svh"


interface RSA_out_monitor_bfm #(
  int AHB_ADDR_WIDTH = 32,
  int AHB_DATA_WIDTH = 32,
  int OUTPUT_TEXT_WIDTH = 4096
  )

  ( RSA_out_if  bus );
  // The pragma below and additional ones in-lined further down are for running this BFM on Veloce
  // pragma attribute RSA_out_monitor_bfm partition_interface_xif                                  

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
      $psprintf("The BFM at '%m' has the following parameters: AHB_ADDR_WIDTH=%x AHB_DATA_WIDTH=%x OUTPUT_TEXT_WIDTH=%x ", AHB_ADDR_WIDTH,AHB_DATA_WIDTH,OUTPUT_TEXT_WIDTH),
      UVM_DEBUG)
end
`endif


  // Structure used to pass transaction data from monitor BFM to monitor class in agent.
`RSA_out_MONITOR_STRUCT
  RSA_out_monitor_s RSA_out_monitor_struct;

  // Structure used to pass configuration data from monitor class to monitor BFM.
 `RSA_out_CONFIGURATION_STRUCT
 

  // Config value to determine if this is an initiator or a responder 
  uvmf_initiator_responder_t initiator_responder;
  // Custom configuration variables.  
  // These are set using the configure function which is called during the UVM connect_phase

  tri clk_i;
  tri rst_n_i;
  tri  hresp_i;
  tri  hreadyout_i;
  tri [AHB_DATA_WIDTH-1:0] hrdata_i;
  tri [31:0] hrdata_32_i;
  tri  transaction_flag_out_monitor_i;
  tri [2:0] test_i;
  tri [2:0] op_i;
  tri [AHB_ADDR_WIDTH-1:0] haddr_i;
  tri  hsel_i;
  tri  hwrite_i;
  tri [1:0] htrans_i;
  assign clk_i = bus.clk;
  assign rst_n_i = bus.rst_n;
  assign hresp_i = bus.hresp;
  assign hreadyout_i = bus.hreadyout;
  assign hrdata_i = bus.hrdata;
  assign hrdata_32_i = bus.hrdata_32;
  assign transaction_flag_out_monitor_i = bus.transaction_flag_out_monitor;
  assign test_i = bus.test;
  assign op_i = bus.op;

  // Runtime key length of the transaction in flight.  Published as
  // rsa_key_size so the scoreboard can mask off the part of the RESULT
  // aperture that a shortened key never writes.
  tri [1:0] keylen_i;
  assign keylen_i = bus.keylen;

  function automatic int unsigned mon_keylen_bits(input bit [1:0] k);
    case (k)
      2'b00   : return 2048;
      2'b01   : return 3072;
      default : return 4096;
    endcase
  endfunction
  assign haddr_i = bus.haddr;
  assign hsel_i = bus.hsel;
  assign hwrite_i = bus.hwrite;
  assign htrans_i = bus.htrans;

  // Proxy handle to UVM monitor
  RSA_out_pkg::RSA_out_monitor #(
    .AHB_ADDR_WIDTH(AHB_ADDR_WIDTH),
    .AHB_DATA_WIDTH(AHB_DATA_WIDTH),
    .OUTPUT_TEXT_WIDTH(OUTPUT_TEXT_WIDTH)
    )
 proxy;
  // pragma tbx oneway proxy.notify_transaction                 

  // pragma uvmf custom interface_item_additional begin
  // pragma uvmf custom interface_item_additional end
  
  //******************************************************************                         
  task wait_for_reset();// pragma tbx xtf  
    @(posedge clk_i) ;                                                                    
    do_wait_for_reset();                                                                   
  endtask                                                                                   

  // ****************************************************************************              
  task do_wait_for_reset(); 
  // pragma uvmf custom reset_condition begin
    wait ( rst_n_i === 1 ) ;                                                              
    @(posedge clk_i) ;                                                                    
  // pragma uvmf custom reset_condition end                                                                
  endtask    

  //******************************************************************                         
 
  task wait_for_num_clocks(input int unsigned count); // pragma tbx xtf 
    @(posedge clk_i);  
                                                                   
    repeat (count-1) @(posedge clk_i);                                                    
  endtask      

  //******************************************************************                         
  event go;                                                                                 
  function void start_monitoring();// pragma tbx xtf    
    -> go;
  endfunction                                                                               
  
  reg transaction_flag;

  //--------------------------------------------------------------------------
  // Aperture reassembly state.
  //
  // The monitor watches the AHB address phase, records which aperture is being
  // read, and reassembles the wide operand from the successive 32-bit beats.
  // Operands are BIG ENDIAN and RIGHT ALIGNED in their aperture, so the first
  // beat of a read is the MOST significant word -- the same convention the
  // driver writes with.  Reassembling with the opposite endianness would give
  // a word-reversed value that still looks plausible, which is exactly the
  // kind of silent miscompare a scoreboard cannot diagnose.
  //
  // ECC's monitor inferred the result identity by counting beats after a flag.
  // That is not sufficient for RSA, which has seven separately readable
  // apertures, so this monitor DECODES the address instead of guessing.
  //--------------------------------------------------------------------------
  localparam bit [31:0]   MON_ADDR_STATUS  = 32'h0000_0018;
  localparam bit [31:0]   MON_ADDR_RESULT  = 32'h0000_1000;
  localparam bit [31:0]   MON_ADDR_PRODUCT = 32'h0000_1200;
  localparam int unsigned MON_RES_REGS     = 128;
  localparam int unsigned MON_PROD_REGS    = 256;

  reg [OUTPUT_TEXT_WIDTH-1:0]   result_acc;
  reg [2*OUTPUT_TEXT_WIDTH-1:0] product_acc;
  reg [31:0]                    status_acc;

  // AHB-Lite is pipelined: hrdata for address A appears one cycle AFTER A was
  // presented.  The address must therefore be latched at the address phase and
  // consumed at the following data phase, not sampled together with the data.
  reg [31:0] pending_addr;
  reg        pending_read;

  reg saw_result;
  reg saw_product;

  reg [2:0]     op;
  reg [2:0]     test;

  // ****************************************************************************              
  initial begin  
    
    transaction_flag = 0;
    pending_read     = 0;
    pending_addr     = 0;
    result_acc       = 0;
    product_acc      = 0;
    status_acc       = 0;
    saw_result       = 0;
    saw_product      = 0;


    @go;                                                                                   
    forever begin
      // do_monitor() owns its own clocking: it spins internally until a
      // complete RSA operation has been observed.  An extra @(posedge) here
      // would make the monitor blind on alternate cycles and drop AHB beats.
      do_monitor( RSA_out_monitor_struct );
                                                                 
 
      proxy.notify_transaction( RSA_out_monitor_struct );
 
    end                                                                                    
  end                                                                                       

  //******************************************************************
  // The configure() function is used to pass agent configuration
  // variables to the monitor BFM.  It is called by the monitor within
  // the agent at the beginning of the simulation.  It may be called 
  // during the simulation if agent configuration variables are updated
  // and the monitor BFM needs to be aware of the new configuration 
  // variables.
  //
    function void configure(RSA_out_configuration_s RSA_out_configuration_arg); // pragma tbx xtf  
    initiator_responder = RSA_out_configuration_arg.initiator_responder;
  // pragma uvmf custom configure begin
  // pragma uvmf custom configure end
  endfunction   


  // ****************************************************************************  
            
  task do_monitor(output RSA_out_monitor_s RSA_out_monitor_struct);
    //
    // Available struct members:
    //     //    RSA_out_monitor_struct.rsa_result
    //     //    RSA_out_monitor_struct.rsa_product_hi
    //     //    RSA_out_monitor_struct.rsa_product_lo
    //     //    RSA_out_monitor_struct.rsa_status
    //     //    RSA_out_monitor_struct.rsa_cycles
    //     //    RSA_out_monitor_struct.rsa_op_observed
    //     //    RSA_out_monitor_struct.rsa_key_size
    //     //
    // Reference code;
    //    How to wait for signal value
    //      while (control_signal === 1'b1) @(posedge clk_i);
    //    
    //    How to assign a struct member, named xyz, from a signal.   
    //    All available input signals listed.
    //      RSA_out_monitor_struct.xyz = hresp_i;  //     
    //      RSA_out_monitor_struct.xyz = hreadyout_i;  //     
    //      RSA_out_monitor_struct.xyz = hrdata_i;  //    [AHB_DATA_WIDTH-1:0] 
    //      RSA_out_monitor_struct.xyz = transaction_flag_out_monitor_i;  //     
    //      RSA_out_monitor_struct.xyz = test_i;  //    [2:0] 
    //      RSA_out_monitor_struct.xyz = op_i;  //    [1:0] 
    // pragma uvmf custom do_monitor begin
    //--------------------------------------------------------------------------
    // Reassemble passive AHB reads into one transaction per completed operation.
    // Publish on the activity flag's falling edge, after all result beats;
    // the rising edge would expose the previous operation's data.
    //--------------------------------------------------------------------------
    if (rst_n_i == 0) begin
      while (rst_n_i == 0) @(posedge clk_i);
      repeat (5) @(posedge clk_i);
      RSA_out_monitor_struct.rsa_result      = 0;
      RSA_out_monitor_struct.rsa_product_hi  = 0;
      RSA_out_monitor_struct.rsa_product_lo  = 0;
      RSA_out_monitor_struct.rsa_status      = 0;
      RSA_out_monitor_struct.rsa_cycles      = 0;
      RSA_out_monitor_struct.rsa_op_observed = 0;
      RSA_out_monitor_struct.rsa_key_size    = 0;

      transaction_flag = 0;
      pending_read     = 0;
      pending_addr     = 0;
      result_acc       = 0;
      product_acc      = 0;
      status_acc       = 0;
      saw_result       = 0;
      saw_product      = 0;
      op               = op_i;
      test             = test_i;
      // Do not return: reset has no expectation. This monitor uses bench rst_n,
      // while the input monitor uses driver-controlled rsa_rst_n.
    end

    begin
      // Each return triggers notify_transaction(); wait for a complete operation.
      forever begin
      @(posedge clk_i);
      op   = op_i;
      test = test_i;

      // Data phase of the address captured on the previous cycle.
      if (pending_read && hreadyout_i) begin
        if (pending_addr == MON_ADDR_STATUS) begin
          status_acc = hrdata_32_i;
        end
        else if ((pending_addr >= MON_ADDR_RESULT) &&
                 (pending_addr <  MON_ADDR_RESULT + 4*MON_RES_REGS)) begin
          // Word index within the aperture, 0 = most significant.
          automatic int unsigned w = (pending_addr - MON_ADDR_RESULT) >> 2;
          result_acc[(MON_RES_REGS-1-w)*32 +: 32] = hrdata_32_i;
          saw_result = 1;
        end
        else if ((pending_addr >= MON_ADDR_PRODUCT) &&
                 (pending_addr <  MON_ADDR_PRODUCT + 4*MON_PROD_REGS)) begin
          automatic int unsigned w = (pending_addr - MON_ADDR_PRODUCT) >> 2;
          product_acc[(MON_PROD_REGS-1-w)*32 +: 32] = hrdata_32_i;
          saw_product = 1;
        end
      end
      pending_read = 0;

      // Address phase: latch a read for the next cycle's data phase.
      if (hsel_i && !hwrite_i && (htrans_i == 2'b10)) begin
        pending_addr = haddr_i;
        pending_read = 1;
      end

      // ---- publish on the falling edge of the driver's activity flag -------
      if (transaction_flag && !transaction_flag_out_monitor_i) begin
        RSA_out_monitor_struct.rsa_result      = result_acc;
        RSA_out_monitor_struct.rsa_product_hi  = product_acc[2*OUTPUT_TEXT_WIDTH-1 -: OUTPUT_TEXT_WIDTH];
        RSA_out_monitor_struct.rsa_product_lo  = product_acc[OUTPUT_TEXT_WIDTH-1 : 0];
        RSA_out_monitor_struct.rsa_status      = status_acc;
        RSA_out_monitor_struct.rsa_cycles      = 0;
        RSA_out_monitor_struct.rsa_op_observed = op;
        RSA_out_monitor_struct.rsa_key_size    = mon_keylen_bits(keylen_i);

        // Prevent operations with no readback from inheriting stale results.
        result_acc  = 0;
        product_acc = 0;
        saw_result  = 0;
        saw_product = 0;

        transaction_flag = transaction_flag_out_monitor_i;
        return;
      end

      transaction_flag = transaction_flag_out_monitor_i;
      end
    end
    // pragma uvmf custom do_monitor end
  endtask         
  
 
endinterface

// pragma uvmf custom external begin
// pragma uvmf custom external end
