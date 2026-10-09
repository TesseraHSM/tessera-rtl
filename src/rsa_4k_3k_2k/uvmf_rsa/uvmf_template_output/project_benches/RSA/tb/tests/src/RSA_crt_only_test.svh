`ifndef __RSA_CRT_ONLY_TEST
`define __RSA_CRT_ONLY_TEST

`include "uvm_macros.svh"

//----------------------------------------------------------------------
// RSA_crt_only_test -- CRT context build and MODEXP_SEC_CRT at 2048/3072/4096.
//
// Requires RSA_CRT_ENABLE_CONFIG; otherwise CRT commands are refused.
// Select phases through RSA_PHASE_MASK, retaining the normal factory override
// to avoid item-cast failures. Power-on reset remains mandatory.
//----------------------------------------------------------------------
class RSA_crt_only_test extends test_top;

  `uvm_component_utils(RSA_crt_only_test)

  function new(string name = "", uvm_component parent = null );
    super.new(name, parent);
  endfunction : new

  virtual function void build_phase(uvm_phase phase );
    RSA_bench_sequence_base::type_id::set_type_override(RSA_normal_sequence #(64,32)::get_type());
    uvm_config_db #(int)::set(null, "*", "RSA_PHASE_MASK", 2);
    super.build_phase(phase);
  endfunction : build_phase

endclass : RSA_crt_only_test

`endif
