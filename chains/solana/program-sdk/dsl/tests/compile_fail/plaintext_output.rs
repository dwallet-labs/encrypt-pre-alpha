// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use encrypt_dsl::prelude::*;

/// Outputs must be encrypted, not plaintext.
#[encrypt_fn_graph]
fn bad(a: EUint64, b: PUint64) -> PUint64 {
    a + b
}

fn main() {}
