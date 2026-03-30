// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use encrypt_dsl::prelude::*;

#[encrypt_fn_graph]
fn bad(a: EUint32) -> EUint32 {
    let c = EUint999::from(42u32);
    a + c
}

fn main() {}
