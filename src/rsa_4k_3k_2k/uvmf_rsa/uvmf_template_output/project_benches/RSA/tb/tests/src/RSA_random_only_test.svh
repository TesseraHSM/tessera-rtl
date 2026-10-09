`ifndef __RSA_RANDOM_ONLY_TEST
`define __RSA_RANDOM_ONLY_TEST

`include "uvm_macros.svh"

//----------------------------------------------------------------------
// RSA_random_only_test -- constrained-random op/width mix plus the two on-the-fly resets.
//
// Isolate seed sweeps and long timeouts: MODEXP_SEC can take ~653k cycles
// at 4096 bits. Include on-the-fly resets for seed-dependent recovery coverage.
// Select phases through RSA_PHASE_MASK, retaining the normal factory override
// to avoid item-cast failures. Power-on reset remains mandatory.
//----------------------------------------------------------------------
class RSA_random_only_test extends test_top;

  `uvm_component_utils(RSA_random_only_test)

  function new(string name = "", uvm_component parent = null );
    super.new(name, parent);
  endfunction : new

  virtual function void build_phase(uvm_phase phase );
    RSA_bench_sequence_base::type_id::set_type_override(RSA_normal_sequence #(64,32)::get_type());
    uvm_config_db #(int)::set(null, "*", "RSA_PHASE_MASK", 12);
    super.build_phase(phase);
  endfunction : build_phase

endclass : RSA_random_only_test

`endif
