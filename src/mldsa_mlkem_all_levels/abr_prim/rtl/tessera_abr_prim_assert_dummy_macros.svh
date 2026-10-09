// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Macro bodies included by tessera_abr_prim_assert.sv for tools that don't support assertions. See
// tessera_abr_prim_assert.sv for documentation for each of the macros.

// Explicitly include the file defining the macros referenced below
// (TESSERA_ABR_ASSERT_DEFAULT_CLK/RST, etc.). Guarded, so it is a no-op when this
// fragment is pulled in via tessera_abr_prim_assert.sv.
`include "tessera_abr_prim_assert.sv"

`define TESSERA_ABR_ASSERT_I(__name, __prop)
`define TESSERA_ABR_ASSERT_INIT(__name, __prop)
`define TESSERA_ABR_ASSERT_INIT_NET(__name, __prop)
`define TESSERA_ABR_ASSERT_FINAL(__name, __prop)
`ifndef TESSERA_ABR_SVA
`define TESSERA_ABR_ASSERT(__name, __prop, __clk = `TESSERA_ABR_ASSERT_DEFAULT_CLK, __rst = `TESSERA_ABR_ASSERT_DEFAULT_RST)
`define TESSERA_ABR_ASSERT_NEVER(__name, __prop, __clk = `TESSERA_ABR_ASSERT_DEFAULT_CLK, __rst = `TESSERA_ABR_ASSERT_DEFAULT_RST)
`define TESSERA_ABR_ASSERT_KNOWN(__name, __sig, __clk = `TESSERA_ABR_ASSERT_DEFAULT_CLK, __rst = `TESSERA_ABR_ASSERT_DEFAULT_RST)
`endif
`define TESSERA_ABR_COVER(__name, __prop, __clk = `TESSERA_ABR_ASSERT_DEFAULT_CLK, __rst = `TESSERA_ABR_ASSERT_DEFAULT_RST)
`define TESSERA_ABR_ASSUME(__name, __prop, __clk = `TESSERA_ABR_ASSERT_DEFAULT_CLK, __rst = `TESSERA_ABR_ASSERT_DEFAULT_RST)
`define TESSERA_ABR_ASSUME_I(__name, __prop)
