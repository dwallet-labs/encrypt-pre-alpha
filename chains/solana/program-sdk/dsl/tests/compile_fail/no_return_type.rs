// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use encrypt_dsl::prelude::*;

/// encrypt_fn must have a return type.
#[encrypt_fn_graph]
fn bad(a: EUint32) {
    let _x = a + a;
}

fn main() {}
