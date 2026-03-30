// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use encrypt_dsl::prelude::*;

/// Unknown vector type name should fail.
#[encrypt_fn_graph]
fn bad(a: EUint32VectorBad) -> EUint32VectorBad {
    a
}

fn main() {}
