//----------------------------------------------------------------------
// Created with uvmf_gen version 2022.3
//----------------------------------------------------------------------
// pragma uvmf custom header begin
// pragma uvmf custom header end
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//
// DESCRIPTION: This package contains test level parameters
//
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//


package RSA_parameters_pkg;

  import uvmf_base_pkg_hdl::*;

  // pragma uvmf custom package_imports_additional begin 
  // pragma uvmf custom package_imports_additional end


  // These parameters are used to uniquely identify each interface.  The monitor_bfm and
  // driver_bfm are placed into and retrieved from the uvm_config_db using these string 
  // names as the field_name. The parameter is also used to enable transaction viewing 
  // from the command line for selected interfaces using the UVM command line processing.
  parameter string RSA_in_agent_BFM  = "RSA_in_agent_BFM"; /* [0] */
  parameter string RSA_out_agent_BFM  = "RSA_out_agent_BFM"; /* [1] */

  // pragma uvmf custom package_item_additional begin
  //--------------------------------------------------------------------------
  // RSA register map.
  //
  // Keep this map aligned with the directed src/rsa_4k_3k_2k/tb/rsa_top_tb.sv.
  //--------------------------------------------------------------------------
  parameter bit [31:0] RSA_ADDR_NAME0   = 32'h0000_0000;
  parameter bit [31:0] RSA_ADDR_VERSION = 32'h0000_0008;
  parameter bit [31:0] RSA_ADDR_CTRL    = 32'h0000_0010;
  parameter bit [31:0] RSA_ADDR_STATUS  = 32'h0000_0018;
  parameter bit [31:0] RSA_ADDR_CONFIG  = 32'h0000_001C;
  parameter bit [31:0] RSA_ADDR_MODULUS = 32'h0000_0400;
  parameter bit [31:0] RSA_ADDR_A       = 32'h0000_0600;
  parameter bit [31:0] RSA_ADDR_B       = 32'h0000_0800;
  parameter bit [31:0] RSA_ADDR_E       = 32'h0000_0A00;
  parameter bit [31:0] RSA_ADDR_D       = 32'h0000_0C00;
  parameter bit [31:0] RSA_ADDR_RESULT  = 32'h0000_1000;
  parameter bit [31:0] RSA_ADDR_PRODUCT = 32'h0000_1200;
  parameter bit [31:0] RSA_ADDR_P       = 32'h0000_1600;
  parameter bit [31:0] RSA_ADDR_Q       = 32'h0000_1700;
  parameter bit [31:0] RSA_ADDR_DP      = 32'h0000_1C00;
  parameter bit [31:0] RSA_ADDR_DQ      = 32'h0000_1D00;
  parameter bit [31:0] RSA_ADDR_QINV    = 32'h0000_1E00;

  // Aperture sizes in 32-bit words. Operands are big-endian and right-aligned:
  // word 0 is most significant; shorter keys occupy higher register indices.
  parameter int unsigned RSA_MOD_REGS  = 128;
  parameter int unsigned RSA_A_REGS    = 128;
  parameter int unsigned RSA_B_REGS    = 128;
  parameter int unsigned RSA_E_REGS    = 4;
  parameter int unsigned RSA_D_REGS    = 130;
  parameter int unsigned RSA_RES_REGS  = 128;
  parameter int unsigned RSA_PROD_REGS = 256;
  parameter int unsigned RSA_CRT_REGS  = 64;

  // Maximum operand widths the environment is built for.
  parameter int unsigned RSA_MAX_KEY_SIZE  = 4096;
  parameter int unsigned RSA_MAX_PROD_SIZE = 8192;

  // STATUS layout: READY[0], VALID[1], ERROR[17:2].
  parameter int unsigned RSA_STATUS_READY_BIT = 0;
  parameter int unsigned RSA_STATUS_VALID_BIT = 1;
  parameter int unsigned RSA_STATUS_ERR_LSB   = 2;
  parameter int unsigned RSA_STATUS_ERR_MSB   = 17;

  // CONFIG layout: KEYLEN[1:0] RO, CRT_SUPPORTED[2] RO.  Entirely read-only.
  // CRT_DISABLE[16], CTRL.KEY_LEN[18:17].
  // Build the whole word together to preserve unrelated fields.
  function automatic bit [31:0] rsa_build_config(input int unsigned exp_len,
                                                 input bit crt_disable,
                                                 input bit [1:0] keylen_shorten);
    return {13'h0, keylen_shorten, crt_disable, 1'b0, 13'(exp_len), 2'h0};
  endfunction

  // Address of register word `w` of an operand that occupies `n_words` of an
  // `n_regs` aperture, honouring the big-endian right-aligned convention.
  function automatic bit [31:0] rsa_word_addr(input bit [31:0] base,
                                              input int unsigned n_regs,
                                              input int unsigned n_words,
                                              input int unsigned w);
    return base + 32'(4*(n_regs - n_words + w));
  endfunction
  // pragma uvmf custom package_item_additional end

endpackage

// pragma uvmf custom external begin
// pragma uvmf custom external end
