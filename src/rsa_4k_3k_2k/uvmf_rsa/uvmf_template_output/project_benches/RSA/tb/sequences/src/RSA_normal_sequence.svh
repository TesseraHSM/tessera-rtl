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


`ifndef __RSA_NORMAL_SEQUENCE
`define __RSA_NORMAL_SEQUENCE

`include "uvm_macros.svh"

class RSA_normal_sequence #(int AHB_DATA_WIDTH = 32,
                            int AHB_ADDR_WIDTH = 32
                            ) extends RSA_bench_sequence_base;

  `uvm_object_utils(RSA_normal_sequence) 

  // Define type and handle for reset sequence
  typedef RSA_in_normal_sequence #(AHB_DATA_WIDTH, AHB_ADDR_WIDTH) RSA_in_normal_sequence_t;
  RSA_in_normal_sequence_t RSA_in_normal_s;
  typedef RSA_in_reset_sequence #(AHB_DATA_WIDTH, AHB_ADDR_WIDTH) RSA_in_reset_sequence_t;
  RSA_in_reset_sequence_t RSA_in_reset_s;
  typedef RSA_in_otf_reset_sequence #(AHB_DATA_WIDTH, AHB_ADDR_WIDTH) RSA_in_otf_reset_sequence_t;
  RSA_in_otf_reset_sequence_t RSA_in_otf_reset_s;
  typedef RSA_in_kat_sequence #(AHB_DATA_WIDTH, AHB_ADDR_WIDTH) RSA_in_kat_sequence_t;
  RSA_in_kat_sequence_t RSA_in_kat_s;
  typedef RSA_in_crt_sequence #(AHB_DATA_WIDTH, AHB_ADDR_WIDTH) RSA_in_crt_sequence_t;
  RSA_in_crt_sequence_t RSA_in_crt_s;
  typedef RSA_in_err_sequence #(AHB_DATA_WIDTH, AHB_ADDR_WIDTH) RSA_in_err_sequence_t;
  RSA_in_err_sequence_t RSA_in_err_s;

  // Bound random runtime: MODEXP_SEC can take ~653k cycles at 4096 bits.
  int unsigned random_ops = 6;

  // ------------------------------------------------------------------
  // Enable all phases by default; focused tests select a subset.
  // Power-on reset is mandatory because rsa_init() releases the DUT.
  // ------------------------------------------------------------------
  bit run_kat    = 1'b1;
  bit run_crt    = 1'b1;
  bit run_random = 1'b1;
  bit run_otf    = 1'b1;
  bit run_err    = 1'b1;

  // Bit positions of the RSA_PHASE_MASK config_db entry the focused tests set.
  localparam int PHASE_BIT_KAT    = 0;
  localparam int PHASE_BIT_CRT    = 1;
  localparam int PHASE_BIT_RANDOM = 2;
  localparam int PHASE_BIT_OTF    = 3;
  localparam int PHASE_BIT_ERR    = 4;
  localparam int PHASE_MASK_ALL   = 5'b11111;

  // ------------------------------------------------------------------
  // Select phases with RSA_PHASE_MASK, preserving the normal sequence's
  // factory override to avoid item-cast failures. An absent mask enables all.
  // ------------------------------------------------------------------
  virtual function void apply_phase_mask();
    int mask;
    // Sequences have no component context; support both empty and glob scopes.
    if (!uvm_config_db #(int)::get(null, "", "RSA_PHASE_MASK", mask))
      if (!uvm_config_db #(int)::get(null, "*", "RSA_PHASE_MASK", mask))
        mask = PHASE_MASK_ALL;
    run_kat    = mask[PHASE_BIT_KAT];
    run_crt    = mask[PHASE_BIT_CRT];
    run_random = mask[PHASE_BIT_RANDOM];
    run_otf    = mask[PHASE_BIT_OTF];
    run_err    = mask[PHASE_BIT_ERR];
    `uvm_info("PHASE_MASK",
              $sformatf("RSA bench phases: kat=%0d crt=%0d random=%0d otf=%0d err=%0d",
                        run_kat, run_crt, run_random, run_otf, run_err), UVM_NONE)
  endfunction : apply_phase_mask
  
  // constructor
  function new(string name = "");
    super.new(name);
  endfunction : new

  virtual task body();
    // Runtime widths for the directed phases.
    rsa_in_keylen_transactions kat_widths[3];
    rsa_in_keylen_transactions crt_widths[3];
    rsa_in_keylen_transactions err_widths[2];

    apply_phase_mask();

    kat_widths = '{rsa_keylen_2048, rsa_keylen_3072, rsa_keylen_4096};
    crt_widths = '{rsa_keylen_2048, rsa_keylen_3072, rsa_keylen_4096};
    // Exercise the refusal ladder at no shortening and maximum shortening.
    err_widths = '{rsa_keylen_4096, rsa_keylen_2048};

    //RSA_in_agent_random_seq = RSA_in_random_sequence#()::type_id::create("RSA_in_agent_random_seq");
    RSA_in_normal_s    = RSA_in_normal_sequence_t::type_id::create("RSA_in_normal_s");
    RSA_in_reset_s     = RSA_in_reset_sequence_t::type_id::create("RSA_in_reset_s");
    RSA_in_otf_reset_s = RSA_in_otf_reset_sequence_t::type_id::create("RSA_in_otf_reset_s");
    RSA_in_kat_s       = RSA_in_kat_sequence_t::type_id::create("RSA_in_kat_s");
    RSA_in_crt_s       = RSA_in_crt_sequence_t::type_id::create("RSA_in_crt_s");
    RSA_in_err_s       = RSA_in_err_sequence_t::type_id::create("RSA_in_err_s");

    fork
      RSA_in_agent_config.wait_for_reset();
      RSA_out_agent_config.wait_for_reset();
    join

    // ------------------------------------------------------------------
    // Phase 0: release the DUT's power-on reset through rsa_init().
    // ------------------------------------------------------------------
    RSA_in_reset_s.start(RSA_in_agent_sequencer);

    // ------------------------------------------------------------------
    // Phase 1: NIST ACVP vectors at all widths, before random stimulus,
    // for quick bring-up checks with independently published answers.
    // ------------------------------------------------------------------
    if (run_kat) foreach (kat_widths[i]) begin
      RSA_in_kat_s.kat_keylen = kat_widths[i];
      RSA_in_kat_s.start(RSA_in_agent_sequencer);
    end

    // ------------------------------------------------------------------
    // Phase 2: CRT at all widths, covering write-only key apertures,
    // key conformance, p/q contexts, Garner recombination and Bellcore checking.
    // ------------------------------------------------------------------
    if (run_crt) foreach (crt_widths[i]) begin
      RSA_in_crt_s.crt_keylen = crt_widths[i];
      RSA_in_crt_s.start(RSA_in_agent_sequencer);
    end

    // ------------------------------------------------------------------
    // Phase 3 -- constrained-random op x width mix.
    // ------------------------------------------------------------------
    if (run_random) repeat (random_ops) RSA_in_normal_s.start(RSA_in_agent_sequencer);

    // ------------------------------------------------------------------
    // Phase 4: assert rsa_rst_n mid-stream, then run a fresh operation.
    // ------------------------------------------------------------------
    if (run_otf) repeat (2) RSA_in_otf_reset_s.start(RSA_in_agent_sequencer);

    // ------------------------------------------------------------------
    // Phase 5: check each targeted refusal's error index and priority,
    // including context invalidation after reset. Run last so later phases
    // cannot inherit deliberately invalid configuration or key material.
    // ------------------------------------------------------------------
    if (run_err) foreach (err_widths[i]) begin
      RSA_in_err_s.err_keylen = err_widths[i];
      RSA_in_err_s.start(RSA_in_agent_sequencer);
    end

    fork
      RSA_in_agent_config.wait_for_num_clocks(50);    
      RSA_out_agent_config.wait_for_num_clocks(50);
    join

    // Include UVM failures in the banner consumed by regression log parsers.
    begin
      uvm_report_server svr = uvm_report_server::get_server();
      int unsigned n_err = svr.get_severity_count(UVM_ERROR)
                         + svr.get_severity_count(UVM_FATAL);
      if (n_err == 0) $display("* TESTCASE PASSED");
      else            $display("* TESTCASE FAILED (%0d UVM_ERROR/UVM_FATAL)", n_err);
    end
  endtask


endclass : RSA_normal_sequence

`endif
