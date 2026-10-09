//----------------------------------------------------------------------
// Created with uvmf_gen version 2022.3
//----------------------------------------------------------------------
// pragma uvmf custom header begin
// pragma uvmf custom header end
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//
// DESCRIPTION: Protocol specific agent class definition
//
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//
class RSA_out_agent #(
     int AHB_ADDR_WIDTH = 32,
     int AHB_DATA_WIDTH = 32,
     int OUTPUT_TEXT_WIDTH = 4096
     )
 extends uvmf_parameterized_agent #(
                    .CONFIG_T(RSA_out_configuration #(
                              .AHB_ADDR_WIDTH(AHB_ADDR_WIDTH),
                              .AHB_DATA_WIDTH(AHB_DATA_WIDTH),
                              .OUTPUT_TEXT_WIDTH(OUTPUT_TEXT_WIDTH)
                              )
),
                    .DRIVER_T(RSA_out_driver #(
                              .AHB_ADDR_WIDTH(AHB_ADDR_WIDTH),
                              .AHB_DATA_WIDTH(AHB_DATA_WIDTH),
                              .OUTPUT_TEXT_WIDTH(OUTPUT_TEXT_WIDTH)
                              )
),
                    .MONITOR_T(RSA_out_monitor #(
                               .AHB_ADDR_WIDTH(AHB_ADDR_WIDTH),
                               .AHB_DATA_WIDTH(AHB_DATA_WIDTH),
                               .OUTPUT_TEXT_WIDTH(OUTPUT_TEXT_WIDTH)
                               )
),
                    .COVERAGE_T(RSA_out_transaction_coverage #(
                                .AHB_ADDR_WIDTH(AHB_ADDR_WIDTH),
                                .AHB_DATA_WIDTH(AHB_DATA_WIDTH),
                                .OUTPUT_TEXT_WIDTH(OUTPUT_TEXT_WIDTH)
                                )
),
                    .TRANS_T(RSA_out_transaction #(
                             .AHB_ADDR_WIDTH(AHB_ADDR_WIDTH),
                             .AHB_DATA_WIDTH(AHB_DATA_WIDTH),
                             .OUTPUT_TEXT_WIDTH(OUTPUT_TEXT_WIDTH)
                             )
)
                    );

  `uvm_component_param_utils( RSA_out_agent #(
                              AHB_ADDR_WIDTH,
                              AHB_DATA_WIDTH,
                              OUTPUT_TEXT_WIDTH
                              )
)

// pragma uvmf custom class_item_additional begin
// pragma uvmf custom class_item_additional end

// ****************************************************************************
// FUNCTION : new()
// This function is the standard SystemVerilog constructor.
//
  function new( string name = "", uvm_component parent = null );
    super.new( name, parent );
  endfunction

// ****************************************************************************
  // FUNCTION: build_phase
  virtual function void build_phase(uvm_phase phase);
// pragma uvmf custom build_phase_pre_super begin
// pragma uvmf custom build_phase_pre_super end
    super.build_phase(phase);
    if (configuration.active_passive == ACTIVE) begin
      // Place sequencer handle into configuration object
      // so that it may be retrieved from configuration 
      // rather than using uvm_config_db
      configuration.sequencer = this.sequencer;
    end
  endfunction
  
endclass

// pragma uvmf custom external begin
// pragma uvmf custom external end

