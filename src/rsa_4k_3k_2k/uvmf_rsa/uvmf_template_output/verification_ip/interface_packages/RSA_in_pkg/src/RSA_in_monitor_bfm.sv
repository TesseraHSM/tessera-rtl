//----------------------------------------------------------------------
// Created with uvmf_gen version 2022.3
//----------------------------------------------------------------------
// pragma uvmf custom header begin
// pragma uvmf custom header end
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//     
// DESCRIPTION: This interface performs the RSA_in signal monitoring.
//      It is accessed by the uvm RSA_in monitor through a virtual
//      interface handle in the RSA_in configuration.  It monitors the
//      signals passed in through the port connection named bus of
//      type RSA_in_if.
//
//     Input signals from the RSA_in_if are assigned to an internal input
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
//                   blocks until an operation on the RSA_in bus is complete.
//
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//
import uvmf_base_pkg_hdl::*;
import RSA_in_pkg_hdl::*;
`include "src/RSA_in_macros.svh"


interface RSA_in_monitor_bfm #(
  int AHB_ADDR_WIDTH = 32,
  int AHB_DATA_WIDTH = 32
  )

  ( RSA_in_if  bus );
  // The pragma below and additional ones in-lined further down are for running this BFM on Veloce
  // pragma attribute RSA_in_monitor_bfm partition_interface_xif                                  

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


  // Structure used to pass transaction data from monitor BFM to monitor class in agent.
`RSA_in_MONITOR_STRUCT
  RSA_in_monitor_s RSA_in_monitor_struct;

  // Structure used to pass configuration data from monitor class to monitor BFM.
 `RSA_in_CONFIGURATION_STRUCT
 

  // Config value to determine if this is an initiator or a responder 
  uvmf_initiator_responder_t initiator_responder;
  // Custom configuration variables.  
  // These are set using the configure function which is called during the UVM connect_phase

  tri clk_i;
  tri rst_n_i;
  tri  rsa_rst_n_i;
  tri [AHB_ADDR_WIDTH-1:0] haddr_i;
  tri [AHB_DATA_WIDTH-1:0] hwdata_i;
  tri  hsel_i;
  tri  hwrite_i;
  tri  hready_i;
  tri [1:0] htrans_i;
  tri [2:0] hsize_i;
  tri [AHB_DATA_WIDTH-1:0] hrdata_i;
  tri  hreadyout_i;
  tri  transaction_flag_out_monitor_i;
  tri [2:0] test_i;
  // 3 bits, not the template's 2: op encodings reach 3'b110 (MODEXP_SEC_CRT).
  tri [2:0] op_i;

  // Sideband stimulus bus -- the operands this transaction was given.  The
  // predictor is fed from THIS monitor, so without these it would know the
  // operation but not the numbers and could not compute an expected result.
  bit [1:0]                     keylen_i;
  bit [RSA_IN_MAX_KEY_SIZE-1:0] modulus_i;
  bit [RSA_IN_MAX_KEY_SIZE-1:0] base_i;
  bit [RSA_IN_MAX_KEY_SIZE-1:0] exponent_i;
  bit [31:0]                    exp_len_i;
  assign keylen_i   = bus.keylen;
  assign modulus_i  = bus.modulus;
  assign base_i     = bus.base;
  assign exponent_i = bus.exponent;
  assign exp_len_i  = bus.exp_len;

  assign clk_i = bus.clk;
  assign rst_n_i = bus.rst_n;
  assign rsa_rst_n_i = bus.rsa_rst_n;
  assign haddr_i = bus.haddr;
  assign hwdata_i = bus.hwdata;
  assign hsel_i = bus.hsel;
  assign hwrite_i = bus.hwrite;
  assign hready_i = bus.hready;
  assign htrans_i = bus.htrans;
  assign hsize_i = bus.hsize;
  assign hrdata_i = bus.hrdata;
  assign hreadyout_i = bus.hreadyout;
  assign transaction_flag_out_monitor_i = bus.transaction_flag_out_monitor;
  assign test_i = bus.test;
  assign op_i = bus.op;

  // Proxy handle to UVM monitor
  RSA_in_pkg::RSA_in_monitor #(
    .AHB_ADDR_WIDTH(AHB_ADDR_WIDTH),
    .AHB_DATA_WIDTH(AHB_DATA_WIDTH)
    )
 proxy;
  // pragma tbx oneway proxy.notify_transaction                 

  // pragma uvmf custom interface_item_additional begin
  reg transaction_flag;
  // Set when the reset branch below has already captured a complete
  // transaction, so the normal wait loop must be skipped for this call.
  reg rst_published;
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
  
  // ****************************************************************************              
  initial begin                                                                             
    @go;                                                                                   
    forever begin                                                                        
      @(posedge clk_i);  
      do_monitor( RSA_in_monitor_struct );
                                                                 
 
      proxy.notify_transaction( RSA_in_monitor_struct );
 
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
    function void configure(RSA_in_configuration_s RSA_in_configuration_arg); // pragma tbx xtf  
    initiator_responder = RSA_in_configuration_arg.initiator_responder;
  // pragma uvmf custom configure begin
  // pragma uvmf custom configure end
  endfunction   


  // ****************************************************************************  
            
  task do_monitor(output RSA_in_monitor_s RSA_in_monitor_struct);
    //
    // Available struct members:
    //     //    RSA_in_monitor_struct.test
    //     //    RSA_in_monitor_struct.op
    //     //
    // Reference code;
    //    How to wait for signal value
    //      while (control_signal === 1'b1) @(posedge clk_i);
    //    
    //    How to assign a struct member, named xyz, from a signal.   
    //    All available input signals listed.
    //      RSA_in_monitor_struct.xyz = rsa_rst_n_i;  //     
    //      RSA_in_monitor_struct.xyz = haddr_i;  //    [AHB_ADDR_WIDTH-1:0] 
    //      RSA_in_monitor_struct.xyz = hwdata_i;  //    [AHB_DATA_WIDTH-1:0] 
    //      RSA_in_monitor_struct.xyz = hsel_i;  //     
    //      RSA_in_monitor_struct.xyz = hwrite_i;  //     
    //      RSA_in_monitor_struct.xyz = hready_i;  //     
    //      RSA_in_monitor_struct.xyz = htrans_i;  //    [1:0] 
    //      RSA_in_monitor_struct.xyz = hsize_i;  //    [2:0] 
    //      RSA_in_monitor_struct.xyz = hrdata_i;  //    [AHB_DATA_WIDTH-1:0] 
    //      RSA_in_monitor_struct.xyz = hreadyout_i;  //     
    //      RSA_in_monitor_struct.xyz = transaction_flag_out_monitor_i;  //     
    //      RSA_in_monitor_struct.xyz = test_i;  //    [2:0] 
    //      RSA_in_monitor_struct.xyz = op_i;  //    [1:0] 
    // pragma uvmf custom do_monitor begin
    // UVMF_CHANGE_ME : Implement protocol monitoring.  The commented reference code 
    // below are examples of how to capture signal values and assign them to 
    // structure members.  All available input signals are listed.  The 'while' 
    // code example shows how to wait for a synchronous flow control signal.  This
    // task should return when a complete transfer has been observed.  Once this task is
    // exited with captured values, it is then called again to wait for and observe 
    // the next transfer. One clock cycle is consumed between calls to do_monitor.
    //------------------------------------------------------------------
    // Publish power-on reset for visibility; the predictor discards it and
    // the out monitor emits no counterpart.
    // On-the-fly reset is part of an operation: fall through to normal capture
    // to avoid a duplicate input transaction, regardless of monitor re-entry timing.
    //------------------------------------------------------------------
    rst_published = 1'b0;
    if (rsa_rst_n_i == 1'b0) begin
      while (rsa_rst_n_i == 1'b0) @(posedge clk_i);
      if (rsa_in_test_transactions'(test_i) == rsa_reset_test) begin
        RSA_in_monitor_struct.test = rsa_in_test_transactions'(test_i);
        RSA_in_monitor_struct.op = rsa_in_op_transactions'(op_i);
        RSA_in_monitor_struct.keylen   = rsa_in_keylen_transactions'(keylen_i);
        RSA_in_monitor_struct.modulus  = modulus_i;
        RSA_in_monitor_struct.base     = base_i;
        RSA_in_monitor_struct.exponent = exponent_i;
        RSA_in_monitor_struct.exp_len  = exp_len_i;
        transaction_flag = 0; //Still want to capture reset tx in the out monitor
        rst_published    = 1'b1;
      end
    end

    if (!rst_published) begin
	    transaction_flag = 0;
	    while (transaction_flag == 0) begin
		    if (transaction_flag_out_monitor_i == 1) begin
          transaction_flag = 1;
          RSA_in_monitor_struct.test = rsa_in_test_transactions'(test_i);
				  RSA_in_monitor_struct.op = rsa_in_op_transactions'(op_i);
          RSA_in_monitor_struct.keylen   = rsa_in_keylen_transactions'(keylen_i);
          RSA_in_monitor_struct.modulus  = modulus_i;
          RSA_in_monitor_struct.base     = base_i;
          RSA_in_monitor_struct.exponent = exponent_i;
          RSA_in_monitor_struct.exp_len  = exp_len_i;
		    end //tx flag monitor = 1
		    @(posedge clk_i);
	    end //tx flag = 0
    end

    // pragma uvmf custom do_monitor end
  endtask         
  
 
endinterface

// pragma uvmf custom external begin
// pragma uvmf custom external end
