//----------------------------------------------------------------------
// Created with uvmf_gen version 2022.3
//----------------------------------------------------------------------
// pragma uvmf custom header begin
// pragma uvmf custom header end
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//                                          
// DESCRIPTION: This environment contains all agents, predictors and
// scoreboards required for the block level design.
//
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//

class RSA_environment  extends uvmf_environment_base #(
    .CONFIG_T( RSA_env_configuration 
  ));
  `uvm_component_utils( RSA_environment )





  typedef RSA_in_agent  RSA_in_agent_t;
  RSA_in_agent_t RSA_in_agent;

  typedef RSA_out_agent  RSA_out_agent_t;
  RSA_out_agent_t RSA_out_agent;




  typedef RSA_predictor #(
                .CONFIG_T(CONFIG_T)
                )
 RSA_pred_t;
  RSA_pred_t RSA_pred;

  typedef uvmf_in_order_scoreboard #(.T(RSA_out_transaction))  RSA_sb_t;
  RSA_sb_t RSA_sb;



  typedef uvmf_virtual_sequencer_base #(.CONFIG_T(RSA_env_configuration)) RSA_vsqr_t;
  RSA_vsqr_t vsqr;

  // pragma uvmf custom class_item_additional begin
  // pragma uvmf custom class_item_additional end
 
// ****************************************************************************
// FUNCTION : new()
// This function is the standard SystemVerilog constructor.
//
  function new( string name = "", uvm_component parent = null );
    super.new( name, parent );
  endfunction

// ****************************************************************************
// FUNCTION: build_phase()
// This function builds all components within this environment.
//
  virtual function void build_phase(uvm_phase phase);
// pragma uvmf custom build_phase_pre_super begin
// pragma uvmf custom build_phase_pre_super end
    super.build_phase(phase);
    RSA_in_agent = RSA_in_agent_t::type_id::create("RSA_in_agent",this);
    RSA_in_agent.set_config(configuration.RSA_in_agent_config);
    RSA_out_agent = RSA_out_agent_t::type_id::create("RSA_out_agent",this);
    RSA_out_agent.set_config(configuration.RSA_out_agent_config);
    RSA_pred = RSA_pred_t::type_id::create("RSA_pred",this);
    RSA_pred.configuration = configuration;
    RSA_sb = RSA_sb_t::type_id::create("RSA_sb",this);

    vsqr = RSA_vsqr_t::type_id::create("vsqr", this);
    vsqr.set_config(configuration);
    configuration.set_vsqr(vsqr);

    // pragma uvmf custom build_phase begin
    // pragma uvmf custom build_phase end
  endfunction

// ****************************************************************************
// FUNCTION: connect_phase()
// This function makes all connections within this environment.  Connections
// typically inclue agent to predictor, predictor to scoreboard and scoreboard
// to agent.
//
  virtual function void connect_phase(uvm_phase phase);
// pragma uvmf custom connect_phase_pre_super begin
// pragma uvmf custom connect_phase_pre_super end
    super.connect_phase(phase);
    RSA_in_agent.monitored_ap.connect(RSA_pred.RSA_in_agent_ae);
    //--------------------------------------------------------------------------
    // Compare monitored results with the native SV model using sideband operands.
    // do_compare selects the operation's aperture and width, excluding latency.
    //--------------------------------------------------------------------------
    RSA_pred.RSA_sb_ap.connect(RSA_sb.expected_analysis_export);
    RSA_out_agent.monitored_ap.connect(RSA_sb.actual_analysis_export);
    // pragma uvmf custom reg_model_connect_phase begin
    // pragma uvmf custom reg_model_connect_phase end
  endfunction

// ****************************************************************************
// FUNCTION: end_of_simulation_phase()
// This function is executed just prior to executing run_phase.  This function
// was added to the environment to sample environment configuration settings
// just before the simulation exits time 0.  The configuration structure is 
// randomized in the build phase before the environment structure is constructed.
// Configuration variables can be customized after randomization in the build_phase
// of the extended test.
// If a sequence modifies values in the configuration structure then the sequence is
// responsible for sampling the covergroup in the configuration if required.
//
  virtual function void start_of_simulation_phase(uvm_phase phase);
     configuration.RSA_configuration_cg.sample();
  endfunction

endclass

// pragma uvmf custom external begin
// pragma uvmf custom external end
