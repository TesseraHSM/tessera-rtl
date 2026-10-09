//----------------------------------------------------------------------
// Created with uvmf_gen version 2022.3
//----------------------------------------------------------------------
// pragma uvmf custom header begin
// pragma uvmf custom header end
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//
// Description: This top level module instantiates all synthesizable
//    static content.  This and tb_top.sv are the two top level modules
//    of the simulation.
//
//    This module instantiates the following:
//        DUT: The Design Under Test
//        Interfaces:  Signal bundles that contain signals connected to DUT
//        Driver BFM's: BFM's that actively drive interface signals
//        Monitor BFM's: BFM's that passively monitor interface signals
//
//----------------------------------------------------------------------

//----------------------------------------------------------------------
//

module hdl_top;

import RSA_parameters_pkg::*;
import uvmf_base_pkg_hdl::*;

  // pragma attribute hdl_top partition_module_xrtl
// pragma uvmf custom clock_generator begin
  bit clk;
  // Instantiate a clk driver
  // tbx clkgen
  initial begin
    clk = 0;
    #0ns;
    forever begin
      clk = ~clk;
      #5ns;
    end
  end
// pragma uvmf custom clock_generator end

// pragma uvmf custom reset_generator begin
  bit rst;
  // Instantiate a rst driver
  // tbx clkgen
  initial begin
    rst = 0;
    #200ns;
    rst =  1;
  end
// pragma uvmf custom reset_generator end

  // pragma uvmf custom module_item_additional begin
    // Match rsa_top_tb's default 32-bit AHB address/data and client data widths.
    wire        transaction_flag_out_monitor_top;
    wire [31:0] hrdata_32_top;
    wire        hreadyout_top;
    wire        hresp_top;
    wire [2:0]  op_top;
    wire [2:0]  test_top;

    wire        busy_top;
    wire        error_intr_top;
    wire        notif_intr_top;

    // The driver polls STATUS.READY over AHB; expose busy_o for pin-level checks.
  // pragma uvmf custom module_item_additional end

  // Instantiate the signal bundle, monitor bfm and driver bfm for each interface.
  // The signal bundle, _if, contains signals to be connected to the DUT.
  // The monitor, monitor_bfm, observes the bus, _if, and captures transactions.
  // The driver, driver_bfm, drives transactions onto the bus, _if.
  RSA_in_if  RSA_in_agent_bus(
     // pragma uvmf custom RSA_in_agent_bus_connections begin
     .clk(clk), .rst_n(rst),
     .hrdata(hrdata_32_top),
     .hreadyout(hreadyout_top),
     .op(op_top),
     .test(test_top),
     .transaction_flag_out_monitor(transaction_flag_out_monitor_top)
     // pragma uvmf custom RSA_in_agent_bus_connections end
     );
  RSA_out_if  RSA_out_agent_bus(
     // pragma uvmf custom RSA_out_agent_bus_connections begin
     .clk(clk), .rst_n(rst),
     .hresp(hresp_top),
     .hrdata(hrdata_32_top),
     .hreadyout(hreadyout_top),
     // Passive address observation lets the monitor identify each read aperture.
     .haddr(RSA_in_agent_bus.haddr),
     .hsel(RSA_in_agent_bus.hsel),
     .hwrite(RSA_in_agent_bus.hwrite),
     .htrans(RSA_in_agent_bus.htrans),
     .op(op_top),
     .test(test_top),
     .keylen(RSA_in_agent_bus.keylen),
     .transaction_flag_out_monitor(transaction_flag_out_monitor_top)
     // pragma uvmf custom RSA_out_agent_bus_connections end
     );
  RSA_in_monitor_bfm  RSA_in_agent_mon_bfm(RSA_in_agent_bus.monitor_port);
  RSA_out_monitor_bfm  RSA_out_agent_mon_bfm(RSA_out_agent_bus.monitor_port);
  RSA_in_driver_bfm  RSA_in_agent_drv_bfm(RSA_in_agent_bus.initiator_port);

  // pragma uvmf custom dut_instantiation begin
  //--------------------------------------------------------------------------
  // DUT.  Default parameters, matching src/rsa_4k_3k_2k/tb/rsa_top_tb.sv:171.
  //
  // tessera_rsa_top has no key-vault, PCR-signing or OCP-LOCK ports.
  //--------------------------------------------------------------------------
  tessera_rsa_top dut (
      .clk              (clk),
      // Agent-driven reset supports mid-test resets independently of bench reset.
      .reset_n          (RSA_in_agent_bus.rsa_rst_n),
      .cptra_pwrgood    (rst),

      .haddr_i          (RSA_in_agent_bus.haddr),
      .hwdata_i         (RSA_in_agent_bus.hwdata),
      .hsel_i           (RSA_in_agent_bus.hsel),
      .hwrite_i         (RSA_in_agent_bus.hwrite),
      .hready_i         (RSA_in_agent_bus.hready),
      .htrans_i         (RSA_in_agent_bus.htrans),
      .hsize_i          (RSA_in_agent_bus.hsize),

      .hresp_o          (hresp_top),
      .hreadyout_o      (hreadyout_top),
      .hrdata_o         (hrdata_32_top),

      .busy_o           (busy_top),
      .error_intr       (error_intr_top),
      .notif_intr       (notif_intr_top),
      .debugUnlock_or_scan_mode_switch (1'b0)
  );
  // pragma uvmf custom dut_instantiation end

  initial begin      // tbx vif_binding_block
    import uvm_pkg::uvm_config_db;
    // The monitor_bfm and driver_bfm for each interface is placed into the uvm_config_db.
    // They are placed into the uvm_config_db using the string names defined in the parameters package.
    // The string names are passed to the agent configurations by test_top through the top level configuration.
    // They are retrieved by the agents configuration class for use by the agent.
    uvm_config_db #( virtual RSA_in_monitor_bfm  )::set( null , UVMF_VIRTUAL_INTERFACES , RSA_in_agent_BFM , RSA_in_agent_mon_bfm );
    uvm_config_db #( virtual RSA_out_monitor_bfm  )::set( null , UVMF_VIRTUAL_INTERFACES , RSA_out_agent_BFM , RSA_out_agent_mon_bfm );
    uvm_config_db #( virtual RSA_in_driver_bfm  )::set( null , UVMF_VIRTUAL_INTERFACES , RSA_in_agent_BFM , RSA_in_agent_drv_bfm  );
  end

endmodule

// pragma uvmf custom external begin
// pragma uvmf custom external end
