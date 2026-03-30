// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use encrypt_dsl::prelude::*;

/// Unknown bit vector type name should fail.
#[encrypt_fn_graph]
fn bad(a: E3BitVector) -> E3BitVector {
    a
}

fn main() {}
