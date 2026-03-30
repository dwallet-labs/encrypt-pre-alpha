// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::parse_macro_input;

/// Compiles an FHE function into a computation graph AND a Solana CPI wrapper.
///
/// Generates two functions:
/// - `fn_name()` -> `Vec<u8>` — the serialized computation graph
/// - `fn_name_cpi()` — Solana CPI wrapper that calls encrypt_core::execute_graph
///
/// The `_cpi` function takes:
/// - `ctx`: any type implementing `EncryptCpi`
/// - `encrypt_execute_accounts`: remaining accounts (input ciphertexts + output ciphertexts)
///
/// The caller is responsible for ordering the accounts correctly:
/// first `num_inputs` input ciphertexts, then output ciphertexts.
/// Output accounts can be the same as input accounts (update mode).
#[proc_macro_attribute]
pub fn encrypt_fn(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let func = parse_macro_input!(item as syn::ItemFn);
    match compile_with_cpi(&func) {
        Ok(tokens) => tokens,
        Err(e) => e.to_compile_error().into(),
    }
}

fn compile_with_cpi(func: &syn::ItemFn) -> Result<TokenStream, syn::Error> {
    let result = encrypt_dsl_compile::compile_graph(func)?;
    let graph_fn = &result.graph_fn;
    let cpi_fn = generate_cpi_wrapper(&result)?;
    Ok(quote! {
        #graph_fn
        #cpi_fn
    }
    .into())
}

/// Generate the `_cpi` wrapper function.
///
/// The generated function takes typed account parameters for each input and output,
/// providing compile-time type safety. It also performs runtime fhe_type verification
/// on input accounts before invoking the CPI.
///
/// The function:
/// 1. Verifies each input account's `fhe_type` matches the graph expectation
/// 2. Serializes the graph
/// 3. Builds instruction data: disc(1) + graph_data_len(2) + graph_data + num_inputs(2)
/// 4. Builds the remaining accounts list (inputs then outputs)
/// 5. Calls `ctx.invoke_execute_graph(ix_data, encrypt_execute_accounts)`
fn generate_cpi_wrapper(
    result: &encrypt_dsl_compile::CompileResult,
) -> Result<proc_macro2::TokenStream, syn::Error> {
    let graph_fn_name = format_ident!("{}", result.fn_name);
    let params = &result.params;
    let output_types = &result.output_types;

    let cpi_name = &graph_fn_name; // method name = graph function name (no _cpi suffix)
    let trait_name = format_ident!("{}Cpi", to_pascal_case(&result.fn_name));

    // Encrypted input parameters — each becomes a typed account parameter
    let encrypted_params: Vec<(&String, &String)> = params
        .iter()
        .filter(|(_, tn)| !encrypt_dsl_compile::is_plaintext_type(tn))
        .map(|(n, t)| (n, t))
        .collect();
    let num_encrypted = encrypted_params.len();

    // Build typed input parameter declarations
    let input_param_decls: Vec<proc_macro2::TokenStream> = encrypted_params
        .iter()
        .map(|(name, type_name)| {
            let ident = format_ident!("{}", name);
            let ty = onchain_type(type_name).unwrap();
            let _ = ty; // type used for fhe_type_id extraction below
            quote! { #ident: Self::Account<'__cpi> }
        })
        .collect();

    // Build typed output parameter declarations
    let output_param_decls: Vec<proc_macro2::TokenStream> = output_types
        .iter()
        .enumerate()
        .map(|(i, _type_name)| {
            let ident = format_ident!("__out_{}", i);
            quote! { #ident: Self::Account<'__cpi> }
        })
        .collect();

    // Build runtime fhe_type verification statements for each input
    let input_verifications: Vec<proc_macro2::TokenStream> = encrypted_params
        .iter()
        .map(|(name, type_name)| {
            let ident = format_ident!("{}", name);
            let ty = onchain_type(type_name).unwrap();
            quote! {
                {
                    let __expected = <#ty as encrypt_types::encrypted::HasFheTypeId>::FHE_TYPE_ID;
                    let __actual = self.read_fhe_type(#ident.clone());
                    if __actual != Some(__expected) {
                        return Err(self.type_mismatch_error());
                    }
                }
            }
        })
        .collect();

    // Build accounts list: inputs then outputs
    let input_account_pushes: Vec<proc_macro2::TokenStream> = encrypted_params
        .iter()
        .map(|(name, _)| {
            let ident = format_ident!("{}", name);
            quote! { __accounts.push(#ident); }
        })
        .collect();

    let output_account_pushes: Vec<proc_macro2::TokenStream> = output_types
        .iter()
        .enumerate()
        .map(|(i, _)| {
            let ident = format_ident!("__out_{}", i);
            quote! { __accounts.push(#ident); }
        })
        .collect();

    let total_accounts = num_encrypted + output_types.len();

    Ok(quote! {
        trait #trait_name: encrypt_dsl::cpi::EncryptCpi {
            fn #cpi_name<'__cpi>(
                &'__cpi self,
                #(#input_param_decls,)*
                #(#output_param_decls,)*
            ) -> core::result::Result<(), Self::Error> {
                // Runtime type verification on inputs
                #(#input_verifications)*

                let __graph = #graph_fn_name();
                let __num_inputs: u8 = #num_encrypted as u8;
                let mut __ix = Vec::with_capacity(1 + 2 + __graph.len() + 1);
                __ix.push(4u8); // execute_graph discriminator
                __ix.extend_from_slice(&(__graph.len() as u16).to_le_bytes());
                __ix.extend_from_slice(&__graph);
                __ix.push(__num_inputs);

                // Build remaining accounts: inputs then outputs
                let mut __accounts: Vec<Self::Account<'__cpi>> = Vec::with_capacity(#total_accounts);
                #(#input_account_pushes)*
                #(#output_account_pushes)*

                self.invoke_execute_graph(&__ix, &__accounts)
            }
        }

        impl<__T: encrypt_dsl::cpi::EncryptCpi> #trait_name for __T {}
    })
}

/// Convert snake_case to PascalCase.
fn to_pascal_case(s: &str) -> String {
    s.split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(c) => c.to_uppercase().chain(chars).collect(),
            }
        })
        .collect()
}

/// Map DSL type alias name to the fully qualified on-chain type tokens.
fn onchain_type(type_name: &str) -> Option<proc_macro2::TokenStream> {
    match type_name {
        // Scalars → Encrypted<Marker>
        "EBool" => {
            Some(quote! { encrypt_types::encrypted::Encrypted<encrypt_types::encrypted::Bool> })
        }
        "EUint8" => {
            Some(quote! { encrypt_types::encrypted::Encrypted<encrypt_types::encrypted::Uint8> })
        }
        "EUint16" => {
            Some(quote! { encrypt_types::encrypted::Encrypted<encrypt_types::encrypted::Uint16> })
        }
        "EUint32" => {
            Some(quote! { encrypt_types::encrypted::Encrypted<encrypt_types::encrypted::Uint32> })
        }
        "EUint64" => {
            Some(quote! { encrypt_types::encrypted::Encrypted<encrypt_types::encrypted::Uint64> })
        }
        "EUint128" => {
            Some(quote! { encrypt_types::encrypted::Encrypted<encrypt_types::encrypted::Uint128> })
        }
        "EUint256" => {
            Some(quote! { encrypt_types::encrypted::Encrypted<encrypt_types::encrypted::Uint256> })
        }
        "EAddress" => {
            Some(quote! { encrypt_types::encrypted::Encrypted<encrypt_types::encrypted::Addr> })
        }
        "EUint512" => {
            Some(quote! { encrypt_types::encrypted::Encrypted<encrypt_types::encrypted::Uint512> })
        }
        "EUint1024" => {
            Some(quote! { encrypt_types::encrypted::Encrypted<encrypt_types::encrypted::Uint1024> })
        }
        "EUint2048" => {
            Some(quote! { encrypt_types::encrypted::Encrypted<encrypt_types::encrypted::Uint2048> })
        }
        "EUint4096" => {
            Some(quote! { encrypt_types::encrypted::Encrypted<encrypt_types::encrypted::Uint4096> })
        }
        "EUint8192" => {
            Some(quote! { encrypt_types::encrypted::Encrypted<encrypt_types::encrypted::Uint8192> })
        }
        "EUint16384" => Some(
            quote! { encrypt_types::encrypted::Encrypted<encrypt_types::encrypted::Uint16384> },
        ),
        "EUint32768" => Some(
            quote! { encrypt_types::encrypted::Encrypted<encrypt_types::encrypted::Uint32768> },
        ),
        "EUint65536" => Some(
            quote! { encrypt_types::encrypted::Encrypted<encrypt_types::encrypted::Uint65536> },
        ),
        // Bit vectors → EncryptedVector<FHE_TYPE, Bool, SIZE>
        "E2BitVector" => Some(
            quote! { encrypt_types::encrypted::EncryptedVector<16, encrypt_types::encrypted::Bool, 2> },
        ),
        "E4BitVector" => Some(
            quote! { encrypt_types::encrypted::EncryptedVector<17, encrypt_types::encrypted::Bool, 4> },
        ),
        "E8BitVector" => Some(
            quote! { encrypt_types::encrypted::EncryptedVector<18, encrypt_types::encrypted::Bool, 8> },
        ),
        "E16BitVector" => Some(
            quote! { encrypt_types::encrypted::EncryptedVector<19, encrypt_types::encrypted::Bool, 16> },
        ),
        "E32BitVector" => Some(
            quote! { encrypt_types::encrypted::EncryptedVector<20, encrypt_types::encrypted::Bool, 32> },
        ),
        "E64BitVector" => Some(
            quote! { encrypt_types::encrypted::EncryptedVector<21, encrypt_types::encrypted::Bool, 64> },
        ),
        "E128BitVector" => Some(
            quote! { encrypt_types::encrypted::EncryptedVector<22, encrypt_types::encrypted::Bool, 128> },
        ),
        "E256BitVector" => Some(
            quote! { encrypt_types::encrypted::EncryptedVector<23, encrypt_types::encrypted::Bool, 256> },
        ),
        "E512BitVector" => Some(
            quote! { encrypt_types::encrypted::EncryptedVector<24, encrypt_types::encrypted::Bool, 512> },
        ),
        "E1024BitVector" => Some(
            quote! { encrypt_types::encrypted::EncryptedVector<25, encrypt_types::encrypted::Bool, 1024> },
        ),
        "E2048BitVector" => Some(
            quote! { encrypt_types::encrypted::EncryptedVector<26, encrypt_types::encrypted::Bool, 2048> },
        ),
        "E4096BitVector" => Some(
            quote! { encrypt_types::encrypted::EncryptedVector<27, encrypt_types::encrypted::Bool, 4096> },
        ),
        "E8192BitVector" => Some(
            quote! { encrypt_types::encrypted::EncryptedVector<28, encrypt_types::encrypted::Bool, 8192> },
        ),
        "E16384BitVector" => Some(
            quote! { encrypt_types::encrypted::EncryptedVector<29, encrypt_types::encrypted::Bool, 16384> },
        ),
        "E32768BitVector" => Some(
            quote! { encrypt_types::encrypted::EncryptedVector<30, encrypt_types::encrypted::Bool, 32768> },
        ),
        "E65536BitVector" => Some(
            quote! { encrypt_types::encrypted::EncryptedVector<31, encrypt_types::encrypted::Bool, 65536> },
        ),
        // Arithmetic vectors → EncryptedVector<FHE_TYPE, ScalarMarker, SIZE>
        "EUint8Vector" => Some(
            quote! { encrypt_types::encrypted::EncryptedVector<32, encrypt_types::encrypted::Uint8, 8192> },
        ),
        "EUint16Vector" => Some(
            quote! { encrypt_types::encrypted::EncryptedVector<33, encrypt_types::encrypted::Uint16, 4096> },
        ),
        "EUint32Vector" => Some(
            quote! { encrypt_types::encrypted::EncryptedVector<34, encrypt_types::encrypted::Uint32, 2048> },
        ),
        "EUint64Vector" => Some(
            quote! { encrypt_types::encrypted::EncryptedVector<35, encrypt_types::encrypted::Uint64, 1024> },
        ),
        "EUint128Vector" => Some(
            quote! { encrypt_types::encrypted::EncryptedVector<36, encrypt_types::encrypted::Uint128, 512> },
        ),
        "EUint256Vector" => Some(
            quote! { encrypt_types::encrypted::EncryptedVector<37, encrypt_types::encrypted::Uint256, 256> },
        ),
        "EUint512Vector" => Some(
            quote! { encrypt_types::encrypted::EncryptedVector<38, encrypt_types::encrypted::Uint512, 128> },
        ),
        "EUint1024Vector" => Some(
            quote! { encrypt_types::encrypted::EncryptedVector<39, encrypt_types::encrypted::Uint1024, 64> },
        ),
        "EUint2048Vector" => Some(
            quote! { encrypt_types::encrypted::EncryptedVector<40, encrypt_types::encrypted::Uint2048, 32> },
        ),
        "EUint4096Vector" => Some(
            quote! { encrypt_types::encrypted::EncryptedVector<41, encrypt_types::encrypted::Uint4096, 16> },
        ),
        "EUint8192Vector" => Some(
            quote! { encrypt_types::encrypted::EncryptedVector<42, encrypt_types::encrypted::Uint8192, 8> },
        ),
        "EUint16384Vector" => Some(
            quote! { encrypt_types::encrypted::EncryptedVector<43, encrypt_types::encrypted::Uint16384, 4> },
        ),
        "EUint32768Vector" => Some(
            quote! { encrypt_types::encrypted::EncryptedVector<44, encrypt_types::encrypted::Uint32768, 2> },
        ),
        // Plaintext scalars → Plaintext<Marker, SIZE>
        "PBool" => {
            Some(quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Bool, 1> })
        }
        "PUint8" => {
            Some(quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Uint8, 1> })
        }
        "PUint16" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Uint16, 2> },
        ),
        "PUint32" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Uint32, 4> },
        ),
        "PUint64" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Uint64, 8> },
        ),
        "PUint128" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Uint128, 16> },
        ),
        "PUint256" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Uint256, 32> },
        ),
        "PAddress" => {
            Some(quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Addr, 32> })
        }
        "PUint512" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Uint512, 64> },
        ),
        "PUint1024" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Uint1024, 128> },
        ),
        "PUint2048" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Uint2048, 256> },
        ),
        "PUint4096" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Uint4096, 512> },
        ),
        "PUint8192" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Uint8192, 1024> },
        ),
        "PUint16384" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Uint16384, 2048> },
        ),
        "PUint32768" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Uint32768, 4096> },
        ),
        "PUint65536" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Uint65536, 8192> },
        ),
        // Plaintext bit vectors → Plaintext<Bool, SIZE>
        "P2BitVector" => {
            Some(quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Bool, 1> })
        }
        "P4BitVector" => {
            Some(quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Bool, 1> })
        }
        "P8BitVector" => {
            Some(quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Bool, 1> })
        }
        "P16BitVector" => {
            Some(quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Bool, 2> })
        }
        "P32BitVector" => {
            Some(quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Bool, 4> })
        }
        "P64BitVector" => {
            Some(quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Bool, 8> })
        }
        "P128BitVector" => {
            Some(quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Bool, 16> })
        }
        "P256BitVector" => {
            Some(quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Bool, 32> })
        }
        "P512BitVector" => {
            Some(quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Bool, 64> })
        }
        "P1024BitVector" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Bool, 128> },
        ),
        "P2048BitVector" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Bool, 256> },
        ),
        "P4096BitVector" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Bool, 512> },
        ),
        "P8192BitVector" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Bool, 1024> },
        ),
        "P16384BitVector" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Bool, 2048> },
        ),
        "P32768BitVector" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Bool, 4096> },
        ),
        "P65536BitVector" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Bool, 8192> },
        ),
        // Plaintext arithmetic vectors → Plaintext<Marker, 8192>
        "PUint8Vector" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Uint8, 8192> },
        ),
        "PUint16Vector" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Uint16, 8192> },
        ),
        "PUint32Vector" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Uint32, 8192> },
        ),
        "PUint64Vector" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Uint64, 8192> },
        ),
        "PUint128Vector" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Uint128, 8192> },
        ),
        "PUint256Vector" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Uint256, 8192> },
        ),
        "PUint512Vector" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Uint512, 8192> },
        ),
        "PUint1024Vector" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Uint1024, 8192> },
        ),
        "PUint2048Vector" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Uint2048, 8192> },
        ),
        "PUint4096Vector" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Uint4096, 8192> },
        ),
        "PUint8192Vector" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Uint8192, 8192> },
        ),
        "PUint16384Vector" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Uint16384, 8192> },
        ),
        "PUint32768Vector" => Some(
            quote! { encrypt_types::encrypted::Plaintext<encrypt_types::encrypted::Uint32768, 8192> },
        ),
        _ => None,
    }
}
