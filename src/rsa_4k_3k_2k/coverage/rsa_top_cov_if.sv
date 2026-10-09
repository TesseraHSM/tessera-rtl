// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// ---------------------------------------------------------------------------
// Programming-model coverage, bound into tessera_rsa_top under FCOV.
// Sample command decisions on accept/reject, not ready, to avoid idle-cycle
// duplicates and capture consistent operands and controls. Internal Montgomery
// scheduling is left to structural coverage so these bins remain schedule-neutral.
// ---------------------------------------------------------------------------

`ifdef FCOV
interface rsa_top_cov_if
  import tessera_rsa_params_pkg::*;
  (
   input logic clk,
   input logic reset_n,
   input logic cptra_pwrgood
  );

  // -------------------------------------------------------------------------
  // Hierarchical taps into tessera_rsa_top.rsa_ctrl_i.
  // -------------------------------------------------------------------------
  logic        cmd_accept;
  // Accept and reject are mutually exclusive; sample each decision separately.
  logic        cmd_reject;
  // On rejection cmd_eff holds the previous command; use cmd_reg instead.
  logic [2:0]  cmd_eff;
  logic [2:0]  cmd_reg;
  logic [1:0]  keylen_shorten;
  logic        crt_ldmod_arm;
  logic        crt_available;
  logic        crt_key_ok;
  logic        zeroize_reg;
  logic        ready_reg;
  logic        valid_reg;
  logic [15:0] cmd_error;

  logic [RSA_KEY_SIZE-1:0] modulus_in;
  logic [RSA_KEY_SIZE-1:0] base_in;

  assign cmd_accept     = tessera_rsa_top.rsa_ctrl_i.cmd_accept;
  assign cmd_reject     = tessera_rsa_top.rsa_ctrl_i.cmd_reject;
  assign cmd_eff        = tessera_rsa_top.rsa_ctrl_i.cmd_eff;
  assign cmd_reg        = tessera_rsa_top.rsa_ctrl_i.cmd_reg;
  assign keylen_shorten = tessera_rsa_top.rsa_ctrl_i.keylen_shorten;
  assign crt_ldmod_arm  = tessera_rsa_top.rsa_ctrl_i.crt_ldmod_arm;
  // CRT availability is fixed at build time.
  assign crt_available  = tessera_rsa_params_pkg::RSA_CRT_ENABLE;
  assign crt_key_ok     = tessera_rsa_top.rsa_ctrl_i.crt_key_ok;
  assign zeroize_reg    = tessera_rsa_top.rsa_ctrl_i.zeroize_reg;
  assign ready_reg      = tessera_rsa_top.rsa_ctrl_i.ready_reg;
  assign valid_reg      = tessera_rsa_top.rsa_ctrl_i.valid_reg;
  assign cmd_error      = 16'(tessera_rsa_top.rsa_ctrl_i.cmd_error);
  assign modulus_in     = tessera_rsa_top.rsa_ctrl_i.modulus_in;
  assign base_in        = tessera_rsa_top.rsa_ctrl_i.base_in;

  // -------------------------------------------------------------------------
  // Classify identity, small, and near-modulus operands to expose arithmetic
  // corner cases, including carry propagation and conditional reduction.
  // -------------------------------------------------------------------------
  localparam logic [RSA_KEY_SIZE-1:0] OPND_ONE_VAL = {{(RSA_KEY_SIZE-1){1'b0}}, 1'b1};

  typedef enum logic [2:0] {
    OPND_ZERO,
    OPND_ONE,
    OPND_SMALL,
    OPND_NEAR_MOD,
    OPND_GENERIC
  } opnd_class_e;

  opnd_class_e base_class;
  opnd_class_e mod_class;

  always_comb begin
    if      (base_in == '0)                                  base_class = OPND_ZERO;
    else if (base_in == OPND_ONE_VAL)                        base_class = OPND_ONE;
    else if (base_in < RSA_KEY_SIZE'(64))                    base_class = OPND_SMALL;
    else if ((modulus_in > RSA_KEY_SIZE'(64)) &&
             (base_in >= (modulus_in - RSA_KEY_SIZE'(64))))  base_class = OPND_NEAR_MOD;
    else                                                     base_class = OPND_GENERIC;
  end

  always_comb begin
    if      (modulus_in == '0)               mod_class = OPND_ZERO;
    else if (modulus_in == OPND_ONE_VAL)     mod_class = OPND_ONE;
    else if (modulus_in < RSA_KEY_SIZE'(64)) mod_class = OPND_SMALL;
    else                                     mod_class = OPND_GENERIC;
  end

  // -------------------------------------------------------------------------
  // Encode the one-hot refusal reason to track each priority-ladder outcome.
  // -------------------------------------------------------------------------
  logic [4:0] err_idx;
  always_comb begin
    err_idx = 5'd31;                       // 31 == "no error"
    for (int unsigned b = 0; b < 16; b++)
      if (cmd_error[b] && (err_idx == 5'd31)) err_idx = 5'(b);
  end

  // -------------------------------------------------------------------------
  // Accepted commands: cmd_error is zero and cmd_eff matches cmd_reg.
  // -------------------------------------------------------------------------
  covergroup rsa_cmd_cg @(posedge clk iff (reset_n && cmd_accept));
    option.per_instance = 1;
    option.name         = "rsa_cmd_cg";

    // Cover the five exercised commands; GENPRIME is not stimulated.
    // NONE and the reserved encoding cannot be accepted.
    cp_cmd : coverpoint cmd_eff {
      bins ldmod          = {3'b001};
      bins modexp_pub     = {3'b010};
      bins modexp_sec     = {3'b011};
      bins mul            = {3'b100};
      bins modexp_sec_crt = {3'b110};
      illegal_bins accepted_no_cmd = {3'b000};
      ignore_bins  not_stimulated  = {3'b101, 3'b111};
    }

    // Cover the programmed encoding, not the derived width, to exercise each
    // key-length decode path.
    cp_shorten : coverpoint keylen_shorten {
      bins full     = {2'd0};
      bins minus_1k = {2'd1};
      bins minus_2k = {2'd2};
      bins minus_3k = {2'd3};
    }

    cp_crt_arm   : coverpoint crt_ldmod_arm;
    cp_crt_avail : coverpoint crt_available;
    cp_crt_key   : coverpoint crt_key_ok;

    cp_base : coverpoint base_class;

    // MUL ignores the modulus, so degenerate values are legal in this group.
    cp_mod : coverpoint mod_class {
      bins usable[]     = {OPND_SMALL, OPND_GENERIC};
      bins degenerate[] = {OPND_ZERO, OPND_ONE};
      ignore_bins impossible = {OPND_NEAR_MOD};  // mod is never near itself
    }

    // Track each command at every width encoding.
    x_cmd_width : cross cp_cmd, cp_shorten;

    // Unarmed CRT commands belong in refusal coverage, not an acceptance cross.
    x_cmd_base : cross cp_cmd, cp_base;
  endgroup

  // -------------------------------------------------------------------------
  // Refused commands, classified by the selected priority-ladder error.
  // -------------------------------------------------------------------------
  covergroup rsa_reject_cg @(posedge clk iff (reset_n && cmd_reject));
    option.per_instance = 1;
    option.name         = "rsa_reject_cg";

    // Sample the attempted opcode, including unsupported commands.
    cp_rej_cmd : coverpoint cmd_reg {
      bins no_cmd         = {3'b000};
      bins ldmod          = {3'b001};
      bins modexp_pub     = {3'b010};
      bins modexp_sec     = {3'b011};
      bins mul            = {3'b100};
      bins genprime       = {3'b101};
      bins modexp_sec_crt = {3'b110};
      bins reserved_111   = {3'b111};
      // NONE cannot assert cmd_reject; its bin intentionally remains unhit.
    }

    cp_err : coverpoint err_idx {
      bins bad_cmd     = {5'd0};
      bins no_context  = {5'd1};
      bins bad_mod     = {5'd2};
      bins bad_base    = {5'd3};
      bins crt_unavail = {5'd4};
      bins mod_range   = {5'd5};
      bins bad_exp_len = {5'd6};
      bins crt_fail    = {5'd7};
      bins bad_keylen  = {5'd8};
      bins mod_fit     = {5'd9};
      // Reject excludes both unassigned indices and the no-error encoding.
      illegal_bins undefined = {[5'd10:5'd15]};
      illegal_bins no_error  = {5'd31};
    }

    cp_rej_mod  : coverpoint mod_class;
    cp_rej_base : coverpoint base_class;

    // Track refusal reasons per command, beyond its highest-priority error.
    x_err_cmd : cross cp_err, cp_rej_cmd;

    // Distinguish an unavailable CRT datapath from invalid CRT key material.
    cp_crt_avail_r : coverpoint crt_available;
    cp_crt_key_r   : coverpoint crt_key_ok;
    x_crt_refusal  : cross cp_rej_cmd, cp_crt_avail_r, cp_crt_key_r {
      ignore_bins non_crt = !binsof(cp_rej_cmd.modexp_sec_crt);
    }
  endgroup

  // Track completion separately from acceptance.
  covergroup rsa_done_cg @(posedge clk iff (reset_n && valid_reg && ready_reg));
    option.per_instance = 1;
    option.name         = "rsa_done_cg";
    cp_done_cmd : coverpoint cmd_eff {
      bins ldmod          = {3'b001};
      bins modexp_pub     = {3'b010};
      bins modexp_sec     = {3'b011};
      bins mul            = {3'b100};
      bins modexp_sec_crt = {3'b110};
    }
    // Do not cross the live keylen_shorten field with a previous command's result.
  endgroup

  // Exercise zeroize both idle and busy, when partial products remain live.
  covergroup rsa_zeroize_cg @(posedge clk iff (reset_n && zeroize_reg));
    option.per_instance = 1;
    option.name         = "rsa_zeroize_cg";
    cp_busy : coverpoint ready_reg {
      bins during_operation = {1'b0};
      bins while_idle       = {1'b1};
    }
  endgroup

  rsa_cmd_cg     rsa_cmd_cg_inst     = new();
  rsa_reject_cg  rsa_reject_cg_inst  = new();
  rsa_done_cg    rsa_done_cg_inst    = new();
  rsa_zeroize_cg rsa_zeroize_cg_inst = new();

endinterface
`endif
