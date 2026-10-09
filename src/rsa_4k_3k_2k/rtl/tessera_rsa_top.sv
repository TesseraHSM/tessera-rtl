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
//======================================================================
//
// tessera_rsa_top
//
// Caliptra RSA engine top level: AHB-Lite slave -> generated register file ->
// command sequencer -> Montgomery datapath.
//
// No Key Vault interface: RSA keys exceed a 512-bit KV entry and are not DICE
// resident.  Private exponents arrive over the bus through write-only RSA_D.
//
// The synthesised key size comes from tessera_rsa_params_pkg (RSA_KEY_SIZE_CONFIG);
// the register aperture is fixed at the RSA-4096 layout for every config.

module tessera_rsa_top
  import tessera_rsa_params_pkg::*;
  import tessera_rsa_reg_pkg::*;
#(
    parameter AHB_ADDR_WIDTH    = 32,
    parameter AHB_DATA_WIDTH    = 32,
    parameter CLIENT_DATA_WIDTH = 32
) (
    input  wire                        clk,
    input  wire                        reset_n,
    input  wire                        cptra_pwrgood,

    // AHB-Lite interface
    input  wire  [AHB_ADDR_WIDTH-1:0]  haddr_i,
    input  wire  [AHB_DATA_WIDTH-1:0]  hwdata_i,
    input  wire                        hsel_i,
    input  wire                        hwrite_i,
    input  wire                        hready_i,
    input  wire  [1:0]                 htrans_i,
    input  wire  [2:0]                 hsize_i,

    output logic                       hresp_o,
    output logic                       hreadyout_o,
    output logic [AHB_DATA_WIDTH-1:0]  hrdata_o,

    output logic                       busy_o,

    output logic                       error_intr,
    output logic                       notif_intr,
    input  logic                       debugUnlock_or_scan_mode_switch
);

  logic                          rsa_cs;
  logic [CLIENT_DATA_WIDTH-1:0]  uc_req_rdata;
  logic                          uc_req_write;
  logic [AHB_ADDR_WIDTH-1:0]     uc_req_addr;
  logic [CLIENT_DATA_WIDTH-1:0]  uc_req_wdata;

  logic rsa_reg_err, rsa_reg_read_err, rsa_reg_write_err;

  rsa_reg__in_t  rsa_reg_hwif_in;
  rsa_reg__out_t rsa_reg_hwif_out;

  ahb_slv_sif #(
      .AHB_ADDR_WIDTH    (AHB_ADDR_WIDTH),
      .AHB_DATA_WIDTH    (AHB_DATA_WIDTH),
      .CLIENT_DATA_WIDTH (CLIENT_DATA_WIDTH)
  ) rsa_ahb_slv_i (
      .hclk       (clk),
      .hreset_n   (reset_n),
      .haddr_i    (haddr_i),
      .hwdata_i   (hwdata_i),
      .hsel_i     (hsel_i),
      .hwrite_i   (hwrite_i),
      .hready_i   (hready_i),
      .htrans_i   (htrans_i),
      .hsize_i    (hsize_i),

      .hresp_o    (hresp_o),
      .hreadyout_o(hreadyout_o),
      .hrdata_o   (hrdata_o),

      .dv         (rsa_cs),
      .hld        ('0),
      .err        (rsa_reg_err),
      .write      (uc_req_write),
      .wdata      (uc_req_wdata),
      .addr       (uc_req_addr),

      .rdata      (uc_req_rdata)
  );

  always_comb rsa_reg_err = rsa_reg_read_err | rsa_reg_write_err;

  tessera_rsa_reg rsa_reg1 (
      .clk (clk),
      .rst (reset_n),

      .s_cpuif_req          (rsa_cs),
      .s_cpuif_req_is_wr    (uc_req_write),
      .s_cpuif_addr         (uc_req_addr[RSA_REG_ADDR_WIDTH-1:0]),
      .s_cpuif_wr_data      (uc_req_wdata),
      .s_cpuif_wr_biten     ('1),
      .s_cpuif_req_stall_wr (),
      .s_cpuif_req_stall_rd (),
      .s_cpuif_rd_ack       (),
      .s_cpuif_rd_err       (rsa_reg_read_err),
      .s_cpuif_rd_data      (uc_req_rdata),
      .s_cpuif_wr_ack       (),
      .s_cpuif_wr_err       (rsa_reg_write_err),

      .hwif_in  (rsa_reg_hwif_in),
      .hwif_out (rsa_reg_hwif_out)
  );

  tessera_rsa_ctrl rsa_ctrl_i (
      .clk           (clk),
      .reset_n       (reset_n),
      .cptra_pwrgood (cptra_pwrgood),

      .hwif_out (rsa_reg_hwif_out),
      .hwif_in  (rsa_reg_hwif_in),

      .busy_o     (busy_o),
      .error_intr (error_intr),
      .notif_intr (notif_intr),
      .debugUnlock_or_scan_mode_switch (debugUnlock_or_scan_mode_switch)
  );

endmodule
