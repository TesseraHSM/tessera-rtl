//----------------------------------------------------------------------
// Created with uvmf_gen version 2022.3
//----------------------------------------------------------------------
// pragma uvmf custom header begin
// pragma uvmf custom header end
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//     
// DESCRIPTION: This class passes transactions between the sequencer
//        and the BFM driver interface.  It accesses the driver BFM 
//        through the bfm handle. This driver
//        passes transactions to the driver BFM through the access
//        task.  
//
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//
class RSA_in_driver  #(
      int AHB_ADDR_WIDTH = 32,
      int AHB_DATA_WIDTH = 32
      )
 extends uvmf_driver_base #(
                   .CONFIG_T(RSA_in_configuration  #(
                             .AHB_ADDR_WIDTH(AHB_ADDR_WIDTH),
                             .AHB_DATA_WIDTH(AHB_DATA_WIDTH)
                             )
 ),
                   .BFM_BIND_T(virtual RSA_in_driver_bfm  #(
                             .AHB_ADDR_WIDTH(AHB_ADDR_WIDTH),
                             .AHB_DATA_WIDTH(AHB_DATA_WIDTH)
                             )
 ),
                   .REQ(RSA_in_transaction  #(
                             .AHB_ADDR_WIDTH(AHB_ADDR_WIDTH),
                             .AHB_DATA_WIDTH(AHB_DATA_WIDTH)
                             )
 ),
                   .RSP(RSA_in_transaction  #(
                             .AHB_ADDR_WIDTH(AHB_ADDR_WIDTH),
                             .AHB_DATA_WIDTH(AHB_DATA_WIDTH)
                             )
 ));

  `uvm_component_param_utils( RSA_in_driver #(
                              AHB_ADDR_WIDTH,
                              AHB_DATA_WIDTH
                              )
)
//*******************************************************************
// Macros that define structs located in RSA_in_macros.svh
//*******************************************************************
// Initiator macro used by RSA_in_driver and RSA_in_driver_bfm
// to communicate initiator driven data to RSA_in_driver_bfm.           
`RSA_in_INITIATOR_STRUCT
  RSA_in_initiator_s RSA_in_initiator_struct;
//*******************************************************************
// Responder macro used by RSA_in_driver and RSA_in_driver_bfm
// to communicate Responder driven data to RSA_in_driver_bfm.
`RSA_in_RESPONDER_STRUCT
  RSA_in_responder_s RSA_in_responder_struct;

// pragma uvmf custom class_item_additional begin
// pragma uvmf custom class_item_additional end

// ****************************************************************************
// This function is the standard SystemVerilog constructor.
//
  function new( string name = "", uvm_component parent=null );
    super.new( name, parent );
  endfunction

// ****************************************************************************
// This function sends configuration object variables to the driver BFM 
// using the configuration struct.
//
  virtual function void configure(input CONFIG_T cfg);
      bfm.configure( cfg.to_struct() );
  endfunction

// ****************************************************************************
// This function places a handle to this class in the proxy variable in the
// driver BFM.  This allows the driver BFM to call tasks and function within this class.
//
  virtual function void set_bfm_proxy_handle();
    bfm.proxy = this;  endfunction

// ****************************************************************************
// Report BFM self-check failures as UVM_ERROR through the proxy.
// Guard callers against a null proxy for standalone BFM use.
//
  virtual function void report_bfm_error(input string msg);
    `uvm_error("RSA_IN_BFM", msg)
  endfunction

// **************************************************************************** 
// This task is called by the run_phase in uvmf_driver_base.              
  virtual task access( inout REQ txn );
// pragma uvmf custom access begin
    if (configuration.initiator_responder==RESPONDER) begin
      // Complete current transfer and wait for next transfer
      bfm.respond_and_wait_for_next_transfer( 
          RSA_in_initiator_struct, 
          txn.to_responder_struct() 
          );
      // Unpack information about initiated transfer received by this responder
      txn.from_initiator_struct(RSA_in_initiator_struct);
    end else begin    
      // Initiate a transfer and get response
      bfm.initiate_and_get_response( 
          txn.to_initiator_struct(), 
          RSA_in_responder_struct 
          );
      // Unpack transfer response information received by this initiator
      txn.from_responder_struct(RSA_in_responder_struct);
    end
// pragma uvmf custom access end
  endtask

endclass

// pragma uvmf custom external begin
// pragma uvmf custom external end
