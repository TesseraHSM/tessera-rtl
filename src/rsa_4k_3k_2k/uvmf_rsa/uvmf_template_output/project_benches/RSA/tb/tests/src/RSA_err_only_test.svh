`ifndef __RSA_ERR_ONLY_TEST
`define __RSA_ERR_ONLY_TEST

`include "uvm_macros.svh"

//----------------------------------------------------------------------
// RSA_err_only_test -- deliberate refusals across the tessera_rsa_ctrl command ladder.
//
// Check targeted error indices for rsa_reject_cg without random-phase cost.
// Select phases through RSA_PHASE_MASK, retaining the normal factory override
// to avoid item-cast failures. Power-on reset remains mandatory.
//----------------------------------------------------------------------
class RSA_err_only_test extends test_top;

  `uvm_component_utils(RSA_err_only_test)

  function new(string name = "", uvm_component parent = null );
    super.new(name, parent);
  endfunction : new

  virtual function void build_phase(uvm_phase phase );
    RSA_bench_sequence_base::type_id::set_type_override(RSA_normal_sequence #(64,32)::get_type());
    uvm_config_db #(int)::set(null, "*", "RSA_PHASE_MASK", 16);
    super.build_phase(phase);
  endfunction : build_phase

  // Refusals leave RESULT unchanged: the BFM suppresses the output activity
  // flag and the predictor emits no expectation, keeping the scoreboard aligned.
  // Disable its empty-activity check only here; the BFM checks STATUS error indices.
  virtual function void end_of_elaboration_phase(uvm_phase phase);
    super.end_of_elaboration_phase(phase);
    environment.RSA_sb.disable_end_of_test_activity_check();
  endfunction : end_of_elaboration_phase

endclass : RSA_err_only_test

`endif
