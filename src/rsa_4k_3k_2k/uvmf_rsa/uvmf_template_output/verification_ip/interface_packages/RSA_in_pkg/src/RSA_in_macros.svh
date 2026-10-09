//----------------------------------------------------------------------
// Created with uvmf_gen version 2022.3
//----------------------------------------------------------------------
// pragma uvmf custom header begin
// pragma uvmf custom header end
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//     
// DESCRIPTION: This file contains macros used with the RSA_in package.
//   These macros include packed struct definitions.  These structs are
//   used to pass data between classes, hvl, and BFM's, hdl.  Use of 
//   structs are more efficient and simpler to modify.
//
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//

// ****************************************************************************
// When changing the contents of this struct, be sure to update the to_struct
//      and from_struct methods defined in the macros below that are used in  
//      the RSA_in_configuration class.
//
  `define RSA_in_CONFIGURATION_STRUCT \
typedef struct packed  { \
     uvmf_active_passive_t active_passive; \
     uvmf_initiator_responder_t initiator_responder; \
     } RSA_in_configuration_s;

  `define RSA_in_CONFIGURATION_TO_STRUCT_FUNCTION \
  virtual function RSA_in_configuration_s to_struct();\
    RSA_in_configuration_struct = \
       {\
       this.active_passive,\
       this.initiator_responder\
       };\
    return ( RSA_in_configuration_struct );\
  endfunction

  `define RSA_in_CONFIGURATION_FROM_STRUCT_FUNCTION \
  virtual function void from_struct(RSA_in_configuration_s RSA_in_configuration_struct);\
      {\
      this.active_passive,\
      this.initiator_responder  \
      } = RSA_in_configuration_struct;\
  endfunction

// ****************************************************************************
// When changing the contents of this struct, be sure to update the to_monitor_struct
//      and from_monitor_struct methods of the RSA_in_transaction class.
//
  `define RSA_in_MONITOR_STRUCT typedef struct packed  { \
  rsa_in_test_transactions test ; \
  rsa_in_op_transactions op ; \
  rsa_in_keylen_transactions keylen ; \
  bit [RSA_IN_MAX_KEY_SIZE-1:0] modulus ; \
  bit [RSA_IN_MAX_KEY_SIZE-1:0] base ; \
  bit [RSA_IN_MAX_KEY_SIZE-1:0] exponent ; \
  bit [31:0] exp_len ; \
     } RSA_in_monitor_s;

  `define RSA_in_TO_MONITOR_STRUCT_FUNCTION \
  virtual function RSA_in_monitor_s to_monitor_struct();\
    RSA_in_monitor_struct = \
            { \
            this.test , \
            this.op , \
            this.keylen , \
            this.modulus , \
            this.base , \
            this.exponent , \
            this.exp_len  \
            };\
    return ( RSA_in_monitor_struct);\
  endfunction\

  `define RSA_in_FROM_MONITOR_STRUCT_FUNCTION \
  virtual function void from_monitor_struct(RSA_in_monitor_s RSA_in_monitor_struct);\
            {\
            this.test , \
            this.op , \
            this.keylen , \
            this.modulus , \
            this.base , \
            this.exponent , \
            this.exp_len  \
            } = RSA_in_monitor_struct;\
  endfunction

// ****************************************************************************
// When changing the contents of this struct, be sure to update the to_initiator_struct
//      and from_initiator_struct methods of the RSA_in_transaction class.
//      Also update the comments in the driver BFM.
//
  `define RSA_in_INITIATOR_STRUCT typedef struct packed  { \
  rsa_in_test_transactions test ; \
  rsa_in_op_transactions op ; \
  rsa_in_keylen_transactions keylen ; \
  bit [RSA_IN_MAX_KEY_SIZE-1:0] modulus ; \
  bit [RSA_IN_MAX_KEY_SIZE-1:0] base ; \
  bit [RSA_IN_MAX_KEY_SIZE-1:0] exponent ; \
  bit [31:0] exp_len ; \
  bit [RSA_IN_MAX_KEY_SIZE/2-1:0] p ; \
  bit [RSA_IN_MAX_KEY_SIZE/2-1:0] q ; \
  bit [RSA_IN_MAX_KEY_SIZE/2-1:0] dp ; \
  bit [RSA_IN_MAX_KEY_SIZE/2-1:0] dq ; \
  bit [RSA_IN_MAX_KEY_SIZE/2-1:0] qinv ; \
  bit [31:0] err_case ; \
     } RSA_in_initiator_s;

  `define RSA_in_TO_INITIATOR_STRUCT_FUNCTION \
  virtual function RSA_in_initiator_s to_initiator_struct();\
    RSA_in_initiator_struct = \
           {\
           this.test , \
           this.op , \
           this.keylen , \
           this.modulus , \
           this.base , \
           this.exponent , \
           this.exp_len , \
           this.p , \
           this.q , \
           this.dp , \
           this.dq , \
           this.qinv , \
           this.err_case  \
           };\
    return ( RSA_in_initiator_struct);\
  endfunction

  `define RSA_in_FROM_INITIATOR_STRUCT_FUNCTION \
  virtual function void from_initiator_struct(RSA_in_initiator_s RSA_in_initiator_struct);\
           {\
           this.test , \
           this.op , \
           this.keylen , \
           this.modulus , \
           this.base , \
           this.exponent , \
           this.exp_len , \
           this.p , \
           this.q , \
           this.dp , \
           this.dq , \
           this.qinv , \
           this.err_case  \
           } = RSA_in_initiator_struct;\
  endfunction

// ****************************************************************************
// When changing the contents of this struct, be sure to update the to_responder_struct
//      and from_responder_struct methods of the RSA_in_transaction class.
//      Also update the comments in the driver BFM.
//
  `define RSA_in_RESPONDER_STRUCT typedef struct packed  { \
  rsa_in_test_transactions test ; \
  rsa_in_op_transactions op ; \
     } RSA_in_responder_s;

  `define RSA_in_TO_RESPONDER_STRUCT_FUNCTION \
  virtual function RSA_in_responder_s to_responder_struct();\
    RSA_in_responder_struct = \
           {\
           this.test , \
           this.op  \
           };\
    return ( RSA_in_responder_struct);\
  endfunction

  `define RSA_in_FROM_RESPONDER_STRUCT_FUNCTION \
  virtual function void from_responder_struct(RSA_in_responder_s RSA_in_responder_struct);\
           {\
           this.test , \
           this.op  \
           } = RSA_in_responder_struct;\
  endfunction
// pragma uvmf custom additional begin
// pragma uvmf custom additional end
