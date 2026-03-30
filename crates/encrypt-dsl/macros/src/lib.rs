// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use proc_macro::TokenStream;
use syn::parse_macro_input;

/// Compiles an FHE function into a computation graph.
///
/// Generates a function that returns a serialized graph as `Vec<u8>`.
/// Chain-agnostic — does not generate any CPI or execution code.
///
/// Use `#[encrypt_fn]` from chain-specific DSL crates for graph + execution wrapper.
#[proc_macro_attribute]
pub fn encrypt_fn_graph(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let func = parse_macro_input!(item as syn::ItemFn);
    match encrypt_dsl_compile::compile_graph(&func) {
        Ok(result) => result.graph_fn.into(),
        Err(e) => e.to_compile_error().into(),
    }
}
