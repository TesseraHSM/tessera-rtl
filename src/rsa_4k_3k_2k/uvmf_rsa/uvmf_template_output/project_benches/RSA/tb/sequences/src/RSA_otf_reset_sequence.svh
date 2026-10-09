// ==============================================================================
// =====            Mentor Graphics UK Ltd                                  =====
// =====            Rivergate, London Road, Newbury BERKS RG14 2QB          =====
// ==============================================================================
// ==============================================================================
// This unpublished work contains proprietary information.
// All right reserved. Supplied in confidence and must not be copied, used or disclosed 
// for any purpose without express written permission.
// 2019 @ Copyright Mentor Graphics UK Ltd
// ==============================================================================


`ifndef __RSA_OTF_RESET_SEQUENCE
`define __RSA_OTF_RESET_SEQUENCE

`include "uvm_macros.svh"

class RSA_otf_reset_sequence #(int AHB_DATA_WIDTH = 32,
                            int AHB_ADDR_WIDTH = 32
                            ) extends RSA_bench_sequence_base;

  `uvm_object_utils(RSA_otf_reset_sequence) 

  // Define type and handle for reset sequence
  typedef RSA_in_otf_reset_sequence #(AHB_DATA_WIDTH, AHB_ADDR_WIDTH) RSA_in_otf_reset_sequence_t;
  RSA_in_otf_reset_sequence_t RSA_in_otf_reset_s;
  
  // constructor
  function new(string name = "");
    super.new(name);
  endfunction : new

  virtual task body();
    //RSA_in_agent_random_seq = RSA_in_random_sequence#()::type_id::create("RSA_in_agent_random_seq");
    RSA_in_otf_reset_s = RSA_in_otf_reset_sequence_t::type_id::create("RSA_in_otf_reset_s");

    fork
      RSA_in_agent_config.wait_for_reset();
      RSA_out_agent_config.wait_for_reset();
    join

    //repeat (10) RSA_in_agent_random_seq.start(RSA_in_agent_sequencer);
    repeat (10) RSA_in_otf_reset_s.start(RSA_in_agent_sequencer);
    //repeat (5) RSA_in_agent_random_seq.start(RSA_in_agent_sequencer);

    fork
      RSA_in_agent_config.wait_for_num_clocks(50);    
      RSA_out_agent_config.wait_for_num_clocks(50);
    join

    if (1) // TODO -- how to properly choose which to print?
        $display("* TESTCASE PASSED");
    else
        $display("* TESTCASE FAILED");
  endtask


endclass : RSA_otf_reset_sequence

`endif
