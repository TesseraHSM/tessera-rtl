// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Macro bodies included by tessera_abr_prim_assert.sv for formal verification with Yosys. See tessera_abr_prim_assert.sv
// for documentation for each of the macros.

// Explicitly include the file defining the macros referenced below
// (TESSERA_ABR_ASSERT_DEFAULT_CLK/RST, etc.). Guarded, so it is a no-op when this
// fragment is pulled in via tessera_abr_prim_assert.sv.
`include "tessera_abr_prim_assert.sv"

`define TESSERA_ABR_ASSERT_I(__name, __prop)    \
  always_comb begin : __name        \
    assert (__prop);                \
  end

`define TESSERA_ABR_ASSERT_INIT(__name, __prop)    \
  initial begin : __name               \
    assert (__prop);                   \
  end

`define TESSERA_ABR_ASSERT_INIT_NET(__name, __prop) \
  initial begin : __name                \
    #1ps assert (__prop);               \
  end

// This doesn't make much sense for a formal tool (we never get to the final block!)
`define TESSERA_ABR_ASSERT_FINAL(__name, __prop)

`ifndef TESSERA_ABR_SVA
`define TESSERA_ABR_ASSERT(__name, __prop, __clk = `TESSERA_ABR_ASSERT_DEFAULT_CLK, __rst = `TESSERA_ABR_ASSERT_DEFAULT_RST) \
  always_ff @(posedge __clk) begin                                                       \
    if (! (__rst !== '0)) __name: assert (__prop);                                       \
  end

`define TESSERA_ABR_ASSERT_NEVER(__name, __prop, __clk = `TESSERA_ABR_ASSERT_DEFAULT_CLK, __rst = `TESSERA_ABR_ASSERT_DEFAULT_RST) \
  always_ff @(posedge __clk) begin                                                             \
    if (! (__rst !== '0)) __name: assert (! (__prop));                                         \
  end

// Yosys uses 2-state logic, so this doesn't make sense here
`define TESSERA_ABR_ASSERT_KNOWN(__name, __sig, __clk = `TESSERA_ABR_ASSERT_DEFAULT_CLK, __rst = `TESSERA_ABR_ASSERT_DEFAULT_RST)
`endif

`define TESSERA_ABR_COVER(__name, __prop, __clk = `TESSERA_ABR_ASSERT_DEFAULT_CLK, __rst = `TESSERA_ABR_ASSERT_DEFAULT_RST) \
  always_ff @(posedge __clk) begin : __name                                             \
    cover ((! (__rst !== '0)) && (__prop));                                             \
  end

`define TESSERA_ABR_ASSUME(__name, __prop, __clk = `TESSERA_ABR_ASSERT_DEFAULT_CLK, __rst = `TESSERA_ABR_ASSERT_DEFAULT_RST) \
  always_ff @(posedge __clk) begin                                                       \
    if (! (__rst !== '0)) __name: assume (__prop);                                       \
  end

`define TESSERA_ABR_ASSUME_I(__name, __prop)              \
  always_comb begin : __name                  \
    assume (__prop);                          \
  end
