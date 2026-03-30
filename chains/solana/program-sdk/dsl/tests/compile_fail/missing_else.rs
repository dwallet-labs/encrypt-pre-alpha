// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use encrypt_dsl::prelude::*;

#[encrypt_fn_graph]
fn bad(flag: EBool, a: EUint32) -> EUint32 {
    let x = if flag { a };
    x
}

fn main() {}
