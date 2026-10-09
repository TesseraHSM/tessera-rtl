//----------------------------------------------------------------------
// Created with uvmf_gen version 2022.3
//----------------------------------------------------------------------
// pragma uvmf custom header begin
// pragma uvmf custom header end
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//     
// DESCRIPTION: This file contains macros used with the RSA_out package.
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
//      the RSA_out_configuration class.
//
  `define RSA_out_CONFIGURATION_STRUCT \
typedef struct packed  { \
     uvmf_active_passive_t active_passive; \
     uvmf_initiator_responder_t initiator_responder; \
     } RSA_out_configuration_s;

  `define RSA_out_CONFIGURATION_TO_STRUCT_FUNCTION \
  virtual function RSA_out_configuration_s to_struct();\
    RSA_out_configuration_struct = \
       {\
       this.active_passive,\
       this.initiator_responder\
       };\
    return ( RSA_out_configuration_struct );\
  endfunction

  `define RSA_out_CONFIGURATION_FROM_STRUCT_FUNCTION \
  virtual function void from_struct(RSA_out_configuration_s RSA_out_configuration_struct);\
      {\
      this.active_passive,\
      this.initiator_responder  \
      } = RSA_out_configuration_struct;\
  endfunction

// ****************************************************************************
// When changing the contents of this struct, be sure to update the to_monitor_struct
//      and from_monitor_struct methods of the RSA_out_transaction class.
//
  `define RSA_out_MONITOR_STRUCT typedef struct packed  { \
  bit [OUTPUT_TEXT_WIDTH-1:0] rsa_result ; \
  bit [OUTPUT_TEXT_WIDTH-1:0] rsa_product_hi ; \
  bit [OUTPUT_TEXT_WIDTH-1:0] rsa_product_lo ; \
  bit [OUTPUT_TEXT_WIDTH-1:0] rsa_status ; \
  bit [OUTPUT_TEXT_WIDTH-1:0] rsa_cycles ; \
  bit [OUTPUT_TEXT_WIDTH-1:0] rsa_op_observed ; \
  bit [OUTPUT_TEXT_WIDTH-1:0] rsa_key_size ; \
     } RSA_out_monitor_s;

  `define RSA_out_TO_MONITOR_STRUCT_FUNCTION \
  virtual function RSA_out_monitor_s to_monitor_struct();\
    RSA_out_monitor_struct = \
            { \
            this.rsa_result , \
            this.rsa_product_hi , \
            this.rsa_product_lo , \
            this.rsa_status , \
            this.rsa_cycles , \
            this.rsa_op_observed , \
            this.rsa_key_size  \
            };\
    return ( RSA_out_monitor_struct);\
  endfunction\

  `define RSA_out_FROM_MONITOR_STRUCT_FUNCTION \
  virtual function void from_monitor_struct(RSA_out_monitor_s RSA_out_monitor_struct);\
            {\
            this.rsa_result , \
            this.rsa_product_hi , \
            this.rsa_product_lo , \
            this.rsa_status , \
            this.rsa_cycles , \
            this.rsa_op_observed , \
            this.rsa_key_size  \
            } = RSA_out_monitor_struct;\
  endfunction

// ****************************************************************************
// When changing the contents of this struct, be sure to update the to_initiator_struct
//      and from_initiator_struct methods of the RSA_out_transaction class.
//      Also update the comments in the driver BFM.
//
  `define RSA_out_INITIATOR_STRUCT typedef struct packed  { \
  bit [OUTPUT_TEXT_WIDTH-1:0] rsa_result ; \
  bit [OUTPUT_TEXT_WIDTH-1:0] rsa_product_hi ; \
  bit [OUTPUT_TEXT_WIDTH-1:0] rsa_product_lo ; \
  bit [OUTPUT_TEXT_WIDTH-1:0] rsa_status ; \
  bit [OUTPUT_TEXT_WIDTH-1:0] rsa_cycles ; \
  bit [OUTPUT_TEXT_WIDTH-1:0] rsa_op_observed ; \
  bit [OUTPUT_TEXT_WIDTH-1:0] rsa_key_size ; \
     } RSA_out_initiator_s;

  `define RSA_out_TO_INITIATOR_STRUCT_FUNCTION \
  virtual function RSA_out_initiator_s to_initiator_struct();\
    RSA_out_initiator_struct = \
           {\
           this.rsa_result , \
           this.rsa_product_hi , \
           this.rsa_product_lo , \
           this.rsa_status , \
           this.rsa_cycles , \
           this.rsa_op_observed , \
           this.rsa_key_size  \
           };\
    return ( RSA_out_initiator_struct);\
  endfunction

  `define RSA_out_FROM_INITIATOR_STRUCT_FUNCTION \
  virtual function void from_initiator_struct(RSA_out_initiator_s RSA_out_initiator_struct);\
           {\
           this.rsa_result , \
           this.rsa_product_hi , \
           this.rsa_product_lo , \
           this.rsa_status , \
           this.rsa_cycles , \
           this.rsa_op_observed , \
           this.rsa_key_size  \
           } = RSA_out_initiator_struct;\
  endfunction

// ****************************************************************************
// When changing the contents of this struct, be sure to update the to_responder_struct
//      and from_responder_struct methods of the RSA_out_transaction class.
//      Also update the comments in the driver BFM.
//
  `define RSA_out_RESPONDER_STRUCT typedef struct packed  { \
  bit [OUTPUT_TEXT_WIDTH-1:0] rsa_result ; \
  bit [OUTPUT_TEXT_WIDTH-1:0] rsa_product_hi ; \
  bit [OUTPUT_TEXT_WIDTH-1:0] rsa_product_lo ; \
  bit [OUTPUT_TEXT_WIDTH-1:0] rsa_status ; \
  bit [OUTPUT_TEXT_WIDTH-1:0] rsa_cycles ; \
  bit [OUTPUT_TEXT_WIDTH-1:0] rsa_op_observed ; \
  bit [OUTPUT_TEXT_WIDTH-1:0] rsa_key_size ; \
     } RSA_out_responder_s;

  `define RSA_out_TO_RESPONDER_STRUCT_FUNCTION \
  virtual function RSA_out_responder_s to_responder_struct();\
    RSA_out_responder_struct = \
           {\
           this.rsa_result , \
           this.rsa_product_hi , \
           this.rsa_product_lo , \
           this.rsa_status , \
           this.rsa_cycles , \
           this.rsa_op_observed , \
           this.rsa_key_size  \
           };\
    return ( RSA_out_responder_struct);\
  endfunction

  `define RSA_out_FROM_RESPONDER_STRUCT_FUNCTION \
  virtual function void from_responder_struct(RSA_out_responder_s RSA_out_responder_struct);\
           {\
           this.rsa_result , \
           this.rsa_product_hi , \
           this.rsa_product_lo , \
           this.rsa_status , \
           this.rsa_cycles , \
           this.rsa_op_observed , \
           this.rsa_key_size  \
           } = RSA_out_responder_struct;\
  endfunction
// pragma uvmf custom additional begin
// pragma uvmf custom additional end
