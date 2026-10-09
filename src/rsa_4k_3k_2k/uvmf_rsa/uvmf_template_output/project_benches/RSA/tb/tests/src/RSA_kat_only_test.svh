`ifndef __RSA_KAT_ONLY_TEST
`define __RSA_KAT_ONLY_TEST

`include "uvm_macros.svh"

//----------------------------------------------------------------------
// RSA_kat_only_test -- NIST ACVP known-answer vectors at 2048/3072/4096.
//
// Fast smoke coverage using vectors with independently published answers.
// Select phases through RSA_PHASE_MASK, retaining the normal factory override
// to avoid item-cast failures. Power-on reset remains mandatory.
//----------------------------------------------------------------------
class RSA_kat_only_test extends test_top;

  `uvm_component_utils(RSA_kat_only_test)

  function new(string name = "", uvm_component parent = null );
    super.new(name, parent);
  endfunction : new

  virtual function void build_phase(uvm_phase phase );
    RSA_bench_sequence_base::type_id::set_type_override(RSA_normal_sequence #(64,32)::get_type());
    uvm_config_db #(int)::set(null, "*", "RSA_PHASE_MASK", 1);
    super.build_phase(phase);
  endfunction : build_phase

endclass : RSA_kat_only_test

`endif
