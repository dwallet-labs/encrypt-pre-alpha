// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use encrypt_dsl::prelude::*;

#[encrypt_fn_graph]
fn bad(a: EUint999) -> EUint999 {
    a
}

fn main() {}
