//----------------------------------------------------------------------
// Created with uvmf_gen version 2022.3
//----------------------------------------------------------------------
// pragma uvmf custom header begin
// pragma uvmf custom header end
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//     
// DESCRIPTION: 
// This file contains defines and typedefs to be compiled for use in
// the simulation running on the emulator when using Veloce.
//
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//
                                                                               

// Test-level stimulus selector, including directed ACVP vectors and refusals.
typedef enum bit[2:0] {
  rsa_reset_test     = 3'b000,
  rsa_normal_test    = 3'b001,
  rsa_otf_reset_test = 3'b010,
  rsa_kat_test       = 3'b011,
  // Expect refusals. RESULT stays stale, so suppress output and prediction
  // transactions and check STATUS in the driver instead.
  rsa_err_test       = 3'b100
} rsa_in_test_transactions;

// Bench operation encodings, translated to CTRL by the driver.
typedef enum bit[2:0] {
  rsa_op_ldmod          = 3'b001,
  rsa_op_modexp_pub     = 3'b010,
  rsa_op_modexp_sec     = 3'b011,
  rsa_op_mul            = 3'b100,
  rsa_op_genprime       = 3'b101,
  rsa_op_modexp_sec_crt = 3'b110
} rsa_in_op_transactions;

// Runtime key length is randomized independently of the operation.
typedef enum bit[1:0] {
  rsa_keylen_2048 = 2'b00,
  rsa_keylen_3072 = 2'b01,
  rsa_keylen_4096 = 2'b10
} rsa_in_keylen_transactions;

// Shared operand width for transactions, structs and sideband. Must match
// RSA_parameters_pkg::RSA_MAX_KEY_SIZE and the driver BFM's MAX_KEY_SIZE.
parameter int unsigned RSA_IN_MAX_KEY_SIZE = 4096;

// Shared enum-to-bit-width mapping for transactions, monitors and predictor.
function automatic int unsigned rsa_keylen_bits(rsa_in_keylen_transactions k);
  case (k)
    rsa_keylen_2048 : return 2048;
    rsa_keylen_3072 : return 3072;
    default         : return 4096;
  endcase
endfunction

// pragma uvmf custom additional begin
// pragma uvmf custom additional end
