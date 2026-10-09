// ==============================================================================
// =====            Mentor Graphics UK Ltd                                  =====
// =====            Rivergate, London Road, Newbury BERKS RG14 2QB          =====
// ==============================================================================
//! @file
//  Project                : RSA
//  Unit                   : RSA_otf_reset_test
//! @brief  Add Class Description Here... 
//-------------------------------------------------------------------------------
//  Created by             : 
//  Creation Date          : 2022/09/29
//-------------------------------------------------------------------------------
// Revision History:
//  URL of HEAD            : $HeadURL$
//  Revision of last commit: $Rev$  
//  Author of last commit  : $Author$
//  Date of last commit    : $Date$  
//
// ==============================================================================
// This unpublished work contains proprietary information.
// All right reserved. Supplied in confidence and must not be copied, used or disclosed 
// for any purpose without express written permission.
// 2019 @ Copyright Mentor Graphics UK Ltd
// ==============================================================================


`ifndef __RSA_OTF_RESET_TEST
`define __RSA_OTF_RESET_TEST

`include "uvm_macros.svh"

class RSA_otf_reset_test extends test_top;

  `uvm_component_utils(RSA_otf_reset_test) 
  
  // constructor
  function new(string name = "", uvm_component parent = null );
    super.new(name, parent);
    // Insert Constructor Code Here
  endfunction : new


  virtual function void build_phase(uvm_phase phase );
    // UVM Factory override. Override RSA_bench_sequence_base with RSA_otf_reset_sequence
    RSA_bench_sequence_base::type_id::set_type_override(RSA_otf_reset_sequence #(64,32)::get_type());
    super.build_phase(phase);
  endfunction : build_phase

endclass : RSA_otf_reset_test

`endif
