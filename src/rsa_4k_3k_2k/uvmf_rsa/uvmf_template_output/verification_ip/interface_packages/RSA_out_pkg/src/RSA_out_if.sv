//----------------------------------------------------------------------
// Created with uvmf_gen version 2022.3
//----------------------------------------------------------------------
// pragma uvmf custom header begin
// pragma uvmf custom header end
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//     
// DESCRIPTION: This interface contains the RSA_out interface signals.
//      It is instantiated once per RSA_out bus.  Bus Functional Models, 
//      BFM's named RSA_out_driver_bfm, are used to drive signals on the bus.
//      BFM's named RSA_out_monitor_bfm are used to monitor signals on the 
//      bus. This interface signal bundle is passed in the port list of
//      the BFM in order to give the BFM access to the signals in this
//      interface.
//
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//
// This template can be used to connect a DUT to these signals
//
// .dut_signal_port(RSA_out_bus.hresp), // Agent input 
// .dut_signal_port(RSA_out_bus.hreadyout), // Agent input 
// .dut_signal_port(RSA_out_bus.hrdata), // Agent input 
// .dut_signal_port(RSA_out_bus.transaction_flag_out_monitor), // Agent input 
// .dut_signal_port(RSA_out_bus.test), // Agent output 
// .dut_signal_port(RSA_out_bus.op), // Agent output 

import uvmf_base_pkg_hdl::*;
import RSA_out_pkg_hdl::*;

interface  RSA_out_if #(
  int AHB_ADDR_WIDTH = 32,
  int AHB_DATA_WIDTH = 32,
  // RSA's widest result (RESULT aperture) is the full key size.  The PRODUCT
  // aperture returned by the MUL command is twice that, so the out-transaction
  // carries both and this parameter sizes the narrower of the two.
  int OUTPUT_TEXT_WIDTH = 4096,
  int PRODUCT_TEXT_WIDTH = 8192
  )


  (
  input tri clk, 
  input tri rst_n,
  inout tri  hresp,
  inout tri  hreadyout,
  inout tri [AHB_DATA_WIDTH-1:0] hrdata,
  // Address-phase signals.  These are NOT in the ECC template: ECC's monitor
  // inferred which result was on the bus by counting read beats after a flag.
  // RSA has seven separately readable apertures (RESULT, PRODUCT, STATUS,
  // CONFIG, CTRL, NAME, VERSION), so blind beat counting cannot tell them
  // apart.  Observing the address makes the monitor decode rather than guess.
  // The out-agent is PASSIVE, so these are observation-only.
  inout tri [AHB_ADDR_WIDTH-1:0] haddr,
  inout tri  hsel,
  inout tri  hwrite,
  inout tri [1:0] htrans,
  inout tri  transaction_flag_out_monitor,
  inout tri [2:0] test,
  inout tri [2:0] op,
  // Runtime key length of the transaction in flight, sourced from the in-agent
  // sideband.  The result monitor needs it to know how many bits of the RESULT
  // aperture are meaningful: for a shortened key the upper registers of the
  // aperture are not written by the operation, so comparing the full 4096 bits
  // would compare stale data.  Declared `input` (not `inout`) because it is
  // connected to an interface variable, which cannot drive an inout port.
  input tri [1:0] keylen
  );

modport monitor_port 
  (
  input clk,
  input rst_n,
  input hresp,
  input hreadyout,
  input hrdata,
  input haddr,
  input hsel,
  input hwrite,
  input htrans,
  input transaction_flag_out_monitor,
  input test,
  input op,
  input keylen
  );

modport initiator_port 
  (
  input clk,
  input rst_n,
  input hresp,
  input hreadyout,
  input hrdata,
  input haddr,
  input hsel,
  input hwrite,
  input htrans,
  input transaction_flag_out_monitor,
  output test,
  output op,
  input keylen
  );

modport responder_port 
  (
  input clk,
  input rst_n,  
  output hresp,
  output hreadyout,
  output hrdata,
  input haddr,
  input hsel,
  input hwrite,
  input htrans,
  output transaction_flag_out_monitor,
  input test,
  input op,
  input keylen
  );
  

// pragma uvmf custom interface_item_additional begin
  // The DUT uses 32-bit AHB data, so no lane recovery is needed.
  wire [31:0] hrdata_32 = hrdata[31:0];
// pragma uvmf custom interface_item_additional end

endinterface

// pragma uvmf custom external begin
// pragma uvmf custom external end
