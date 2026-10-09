//----------------------------------------------------------------------
// Created with uvmf_gen version 2022.3
//----------------------------------------------------------------------
// pragma uvmf custom header begin
// pragma uvmf custom header end
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//     
// DESCRIPTION: 
// This sequences randomizes the RSA_in transaction and sends it 
// to the UVM driver.
//
// This sequence constructs and randomizes a RSA_in_transaction.
// 
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//
class RSA_in_reset_sequence #(
    int AHB_DATA_WIDTH = 32,
    int AHB_ADDR_WIDTH = 32
    )
extends RSA_in_sequence_base #(
    .AHB_DATA_WIDTH(AHB_DATA_WIDTH),
    .AHB_ADDR_WIDTH(AHB_ADDR_WIDTH)

    );

`uvm_object_param_utils( RSA_in_reset_sequence #(
                         AHB_DATA_WIDTH,
                         AHB_ADDR_WIDTH
                         ))

// pragma uvmf custom class_item_additional begin
// pragma uvmf custom class_item_additional end

//*****************************************************************
function new(string name = "");
  super.new(name);
endfunction: new

// ****************************************************************************
// TASK : body()
// This task is automatically executed when this sequence is started using the 
// start(sequencerHandle) task.
//
task body();
  begin
    // Construct the transaction
    req=RSA_in_transaction#(
              .AHB_DATA_WIDTH(AHB_DATA_WIDTH),
              .AHB_ADDR_WIDTH(AHB_ADDR_WIDTH)
              )::type_id::create("req");
    start_item(req);
    // Randomize the transaction
      // Only rsa_reset_test dispatches to rsa_init() to release the DUT reset.
      if(!req.randomize() with { test == rsa_reset_test; }) `uvm_fatal("SEQ", "RSA_in_reset_sequence::body()-RSA_in_transaction randomization failed")
    // set the operation to be a reset
    //req.op = reset_op;
    // Send the transaction to the RSA_in_driver_bfm via the sequencer and RSA_in_driver.
    finish_item(req);
    `uvm_info("SEQ", {"Response:",req.convert2string()},UVM_MEDIUM)
  end

endtask

endclass: RSA_in_reset_sequence
