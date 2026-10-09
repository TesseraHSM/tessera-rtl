//----------------------------------------------------------------------
// Created with uvmf_gen version 2022.3
//----------------------------------------------------------------------
// pragma uvmf custom header begin
// pragma uvmf custom header end
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//     
// DESCRIPTION: This interface contains the RSA_in interface signals.
//      It is instantiated once per RSA_in bus.  Bus Functional Models, 
//      BFM's named RSA_in_driver_bfm, are used to drive signals on the bus.
//      BFM's named RSA_in_monitor_bfm are used to monitor signals on the 
//      bus. This interface signal bundle is passed in the port list of
//      the BFM in order to give the BFM access to the signals in this
//      interface.
//
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//
// This template can be used to connect a DUT to these signals
//
// .dut_signal_port(RSA_in_bus.rsa_rst_n), // Agent output 
// .dut_signal_port(RSA_in_bus.haddr), // Agent output 
// .dut_signal_port(RSA_in_bus.hwdata), // Agent output 
// .dut_signal_port(RSA_in_bus.hsel), // Agent output 
// .dut_signal_port(RSA_in_bus.hwrite), // Agent output 
// .dut_signal_port(RSA_in_bus.hready), // Agent output 
// .dut_signal_port(RSA_in_bus.htrans), // Agent output 
// .dut_signal_port(RSA_in_bus.hsize), // Agent output 
// .dut_signal_port(RSA_in_bus.hrdata), // Agent input 
// .dut_signal_port(RSA_in_bus.hreadyout), // Agent input 
// .dut_signal_port(RSA_in_bus.transaction_flag_out_monitor), // Agent output 
// .dut_signal_port(RSA_in_bus.test), // Agent output 
// .dut_signal_port(RSA_in_bus.op), // Agent output 

import uvmf_base_pkg_hdl::*;
import RSA_in_pkg_hdl::*;

interface  RSA_in_if #(
  int AHB_ADDR_WIDTH = 32,
  int AHB_DATA_WIDTH = 32
  )


  (
  input tri clk, 
  input tri rst_n,
  inout tri  rsa_rst_n,
  inout tri [AHB_ADDR_WIDTH-1:0] haddr,
  inout tri [AHB_DATA_WIDTH-1:0] hwdata,
  inout tri  hsel,
  inout tri  hwrite,
  inout tri  hready,
  inout tri [1:0] htrans,
  inout tri [2:0] hsize,
  inout tri [AHB_DATA_WIDTH-1:0] hrdata,
  inout tri  hreadyout,
  inout tri  transaction_flag_out_monitor,
  inout tri [2:0] test,
  inout tri [2:0] op
  );

//--------------------------------------------------------------------------
// TB-only sideband carries driver operands through the input monitor to the
// predictor, like test/op; these are not DUT pins.
// Interface variables avoid wide tri-state resolution and are visible through
// all three modports.
//--------------------------------------------------------------------------
  bit [1:0]                      keylen;
  bit [RSA_IN_MAX_KEY_SIZE-1:0]  modulus;
  bit [RSA_IN_MAX_KEY_SIZE-1:0]  base;
  bit [RSA_IN_MAX_KEY_SIZE-1:0]  exponent;
  bit [31:0]                     exp_len;

modport monitor_port 
  (
  input clk,
  input rst_n,
  input rsa_rst_n,
  input haddr,
  input hwdata,
  input hsel,
  input hwrite,
  input hready,
  input htrans,
  input hsize,
  input hrdata,
  input hreadyout,
  input transaction_flag_out_monitor,
  input test,
  input op,
  input keylen,
  input modulus,
  input base,
  input exponent,
  input exp_len
  );

modport initiator_port 
  (
  input clk,
  input rst_n,
  output rsa_rst_n,
  output haddr,
  output hwdata,
  output hsel,
  output hwrite,
  output hready,
  output htrans,
  output hsize,
  input hrdata,
  input hreadyout,
  output transaction_flag_out_monitor,
  output test,
  output op,
  output keylen,
  output modulus,
  output base,
  output exponent,
  output exp_len
  );

modport responder_port 
  (
  input clk,
  input rst_n,  
  input rsa_rst_n,
  input haddr,
  input hwdata,
  input hsel,
  input hwrite,
  input hready,
  input htrans,
  input hsize,
  output hrdata,
  output hreadyout,
  input transaction_flag_out_monitor,
  input test,
  input op,
  input keylen,
  input modulus,
  input base,
  input exponent,
  input exp_len
  );
  

// pragma uvmf custom interface_item_additional begin
// pragma uvmf custom interface_item_additional end

endinterface

// pragma uvmf custom external begin
// pragma uvmf custom external end
