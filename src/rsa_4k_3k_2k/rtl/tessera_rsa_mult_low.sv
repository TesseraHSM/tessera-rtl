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
// tessera_rsa_mult_low.sv
// ---------------
// Combinational unsigned product modulo 2^RADIX.
//
// Description:
//      Used for the quotient digit and its precomputed bn0 constant.
//      Separate from tessera_rsa_mult_dsp so synthesis or macro substitution can
//      omit upper-half partial products and carry logic.
//
//======================================================================

module tessera_rsa_mult_low #(
    parameter RADIX = 32
)
(
    // DATA PORT
    input  wire [RADIX-1:0]    A,
    input  wire [RADIX-1:0]    B,

    output logic [RADIX-1:0]   P
);

    always_comb begin
        P = RADIX'(A * B);
    end

endmodule
