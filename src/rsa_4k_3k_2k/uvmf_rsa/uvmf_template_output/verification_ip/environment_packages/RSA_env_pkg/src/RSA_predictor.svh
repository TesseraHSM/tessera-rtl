//----------------------------------------------------------------------
// Created with uvmf_gen version 2022.3
//----------------------------------------------------------------------
// pragma uvmf custom header begin
// pragma uvmf custom header end
//----------------------------------------------------------------------
//
//----------------------------------------------------------------------
//
// DESCRIPTION: This analysis component contains analysis_exports for receiving
//   data and analysis_ports for sending data.
// 
//   This analysis component has the following analysis_exports that receive the 
//   listed transaction type.
//   
//   RSA_in_agent_ae receives transactions of type  RSA_in_transaction #()
//
//   This analysis component has the following analysis_ports that can broadcast 
//   the listed transaction type.
//
//  RSA_sb_ap broadcasts transactions of type RSA_out_transaction #()
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//

class RSA_predictor #(
  type CONFIG_T,
  type BASE_T = uvm_component
  )
 extends BASE_T;

  // Factory registration of this class
  `uvm_component_param_utils( RSA_predictor #(
                              CONFIG_T,
                              BASE_T
                              )
)


  // Instantiate a handle to the configuration of the environment in which this component resides
  CONFIG_T configuration;

  
  // Instantiate the analysis exports
  uvm_analysis_imp_RSA_in_agent_ae #(RSA_in_transaction #(), RSA_predictor #(
                              .CONFIG_T(CONFIG_T),
                              .BASE_T(BASE_T)
                              )
) RSA_in_agent_ae;

  
  // Instantiate the analysis ports
  uvm_analysis_port #(RSA_out_transaction #()) RSA_sb_ap;


  // Transaction variable for predicted values to be sent out RSA_sb_ap
  // Once a transaction is sent through an analysis_port, another transaction should
  // be constructed for the next predicted transaction. 
  typedef RSA_out_transaction #() RSA_sb_ap_output_transaction_t;
  RSA_sb_ap_output_transaction_t RSA_sb_ap_output_transaction;
  // Code for sending output transaction out through RSA_sb_ap
  // RSA_sb_ap.write(RSA_sb_ap_output_transaction);

  // Define transaction handles for debug visibility 
  RSA_in_transaction #() RSA_in_agent_ae_debug;


  // pragma uvmf custom class_item_additional begin
  // Expected results are computed from monitored operands in SystemVerilog.
  // pragma uvmf custom class_item_additional end

  // FUNCTION: new
  function new(string name, uvm_component parent);
     super.new(name,parent);
  // pragma uvmf custom new begin
  // pragma uvmf custom new end
  endfunction

  // FUNCTION: build_phase
  virtual function void build_phase (uvm_phase phase);

    RSA_in_agent_ae = new("RSA_in_agent_ae", this);
    RSA_sb_ap =new("RSA_sb_ap", this );
  // pragma uvmf custom build_phase begin
  // pragma uvmf custom build_phase end
  endfunction

  // FUNCTION: write_RSA_in_agent_ae
  // Transactions received through RSA_in_agent_ae initiate the execution of this function.
  // This function performs prediction of DUT output values based on DUT input, configuration and state
  virtual function void write_RSA_in_agent_ae(RSA_in_transaction #() t);
    // pragma uvmf custom RSA_in_agent_ae_predictor begin
    int unsigned key_bits;
    ref_word_t   exp_result;
    ref_dword_t  exp_product;

    RSA_in_agent_ae_debug = t;

    // Reset has no output transaction; suppress its expectation to keep
    // the in-order scoreboard aligned.
    if (t.test == rsa_reset_test) begin
      `uvm_info("PRED", "Reset transaction: no expectation generated", UVM_MEDIUM)
      return;
    end

    // Refusals leave RESULT stale. The driver BFM checks STATUS's error index;
    // neither monitor output nor a scoreboard expectation is produced.
    if (t.test == rsa_err_test) begin
      `uvm_info("PRED", "Error-injection transaction: no expectation generated", UVM_MEDIUM)
      return;
    end

    `uvm_info("PRED", "Transaction Received through RSA_in_agent_ae", UVM_MEDIUM)
    `uvm_info("PRED", {"            Data: ",t.convert2string()}, UVM_FULL)

    RSA_sb_ap_output_transaction = RSA_sb_ap_output_transaction_t::type_id::create("RSA_sb_ap_output_transaction");

    // Predict from the in-agent sideband operands. Status and cycles are
    // excluded from do_compare; latency belongs to the directed regression.
    key_bits = rsa_keylen_bits(t.keylen);

    exp_result     = '0;
    exp_product    = '0;

    case (t.op)
      rsa_op_mul : begin
        // MUL reuses base/exponent as its two factors and performs no
        // reduction, so the expected value is the full 2N-bit product.
        exp_product = ref_dword_t'(t.base) * ref_dword_t'(t.exponent);
      end

      // Check CRT independently with plain base^d mod n. The sequence supplies
      // d in exponent for the model; the DUT receives only dp/dq/qinv.
      rsa_op_modexp_sec_crt,
      rsa_op_modexp_pub,
      rsa_op_modexp_sec : begin
        // exp_len is an MSB index; ref_mod_exp needs the count exp_len+1.
        exp_result = ref_mod_exp(t.base, t.exponent, t.modulus, t.exp_len + 1);
      end

      // LDMOD only builds context; publish op/key size to align with the monitor.
      default : ;
    endcase

    RSA_sb_ap_output_transaction.rsa_result      = exp_result;
    RSA_sb_ap_output_transaction.rsa_product_hi  = exp_product[2*RSA_IN_MAX_KEY_SIZE-1 -: RSA_IN_MAX_KEY_SIZE];
    RSA_sb_ap_output_transaction.rsa_product_lo  = exp_product[RSA_IN_MAX_KEY_SIZE-1 : 0];
    RSA_sb_ap_output_transaction.rsa_status      = 0;
    RSA_sb_ap_output_transaction.rsa_cycles      = 0;
    RSA_sb_ap_output_transaction.rsa_op_observed = t.op;
    RSA_sb_ap_output_transaction.rsa_key_size    = key_bits;

    RSA_sb_ap.write(RSA_sb_ap_output_transaction);
    // pragma uvmf custom RSA_in_agent_ae_predictor end
  endfunction


endclass 

// pragma uvmf custom external begin
// pragma uvmf custom external end
