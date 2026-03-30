// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use quote::{format_ident, quote};
use std::collections::HashMap;
use syn::{BinOp, Expr, FnArg, ItemFn, Pat, Stmt, Type, UnOp};

// ── Compiler state ──

pub struct Ctx {
    pub vars: HashMap<String, u8>, // var_name -> fhe_type_id
    pub stmts: Vec<proc_macro2::TokenStream>,
    pub temp_id: u32,
}

impl Default for Ctx {
    fn default() -> Self {
        Self::new()
    }
}

impl Ctx {
    pub fn new() -> Self {
        Self {
            vars: HashMap::new(),
            stmts: Vec::new(),
            temp_id: 0,
        }
    }

    pub fn temp(&mut self) -> String {
        let name = format!("__t{}", self.temp_id);
        self.temp_id += 1;
        name
    }
}

// ── Compile result ──

pub struct CompileResult {
    pub graph_fn: proc_macro2::TokenStream,
    pub fn_name: String,
    pub params: Vec<(String, String)>,
    pub output_types: Vec<String>,
}

// ── Main entry ──

pub fn compile_graph(func: &ItemFn) -> Result<CompileResult, syn::Error> {
    let name = &func.sig.ident;
    let mut ctx = Ctx::new();

    ctx.stmts
        .push(quote! { let mut __gb = encrypt_dsl::graph::GraphBuilder::new(); });

    // Collect parameter info for CPI wrapper
    let mut param_info: Vec<(String, String)> = Vec::new(); // (name, type_name)

    // Parameters -> Input or PlaintextInput nodes
    for param in &func.sig.inputs {
        match param {
            FnArg::Typed(pt) => {
                let var = pat_ident(&pt.pat)?;
                let type_name = resolve_type_name(&pt.ty)?;
                let tid = type_id(&type_name).ok_or_else(|| {
                    syn::Error::new_spanned(&pt.ty, format!("unknown FHE type: {type_name}"))
                })?;
                let vi = format_ident!("{}", var);
                if is_plaintext_type(&type_name) {
                    ctx.stmts
                        .push(quote! { let #vi = __gb.add_plaintext_input(#tid); });
                } else {
                    ctx.stmts.push(quote! { let #vi = __gb.add_input(#tid); });
                }
                ctx.vars.insert(var.clone(), tid);
                param_info.push((var, type_name));
            }
            _ => return Err(syn::Error::new_spanned(param, "self not supported")),
        }
    }

    // Parse return type
    let output_type_names = parse_return_types(&func.sig.output)?;

    // Body statements
    for stmt in &func.block.stmts {
        match stmt {
            Stmt::Local(local) => {
                let var = pat_ident(&local.pat)?;
                if let Some(init) = &local.init {
                    let (rhs, tid) = expr(&init.expr, &mut ctx)?;
                    let vi = format_ident!("{}", var);
                    ctx.stmts.push(quote! { let #vi = #rhs; });
                    ctx.vars.insert(var, tid);
                }
            }
            Stmt::Expr(e, _) => {
                emit_outputs(e, &mut ctx)?;
            }
            _ => {}
        }
    }

    let body = &ctx.stmts;
    let graph_fn = quote! {
        fn #name() -> Vec<u8> {
            #(#body)*
            __gb.serialize()
        }
    };

    Ok(CompileResult {
        graph_fn,
        fn_name: name.to_string(),
        params: param_info,
        output_types: output_type_names,
    })
}

// ── Expression compiler ──
// Returns (tokens_that_evaluate_to_u16_node_id, fhe_type_id)

pub fn expr(e: &Expr, ctx: &mut Ctx) -> Result<(proc_macro2::TokenStream, u8), syn::Error> {
    match e {
        // Variable reference
        Expr::Path(p) => {
            let name = path_ident(p)?;
            let tid = *ctx
                .vars
                .get(&name)
                .ok_or_else(|| syn::Error::new_spanned(p, format!("unknown: {name}")))?;
            let vi = format_ident!("{}", name);
            Ok((quote! { #vi }, tid))
        }

        // &x -> unwrap reference
        Expr::Reference(r) => expr(&r.expr, ctx),

        // Parenthesized: (x)
        Expr::Paren(p) => expr(&p.expr, ctx),

        // a.method(&b) or a.method()
        Expr::MethodCall(mc) => {
            let (recv_tok, recv_tid) = expr(&mc.receiver, ctx)?;

            match mc.method.to_string().as_str() {
                // Select (ternary)
                "select" => {
                    if mc.args.len() != 2 {
                        return Err(syn::Error::new_spanned(&mc.method, "select needs 2 args"));
                    }
                    let (a_tok, a_tid) = expr(&mc.args[0], ctx)?;
                    let (b_tok, _) = expr(&mc.args[1], ctx)?;
                    let tmp = ctx.temp();
                    let ti = format_ident!("{}", tmp);
                    ctx.stmts.push(
                        quote! { let #ti = __gb.add_ternary_op(60u8, #a_tid, #recv_tok, #a_tok, #b_tok); },
                    );
                    ctx.vars.insert(tmp.clone(), a_tid);
                    Ok((quote! { #ti }, a_tid))
                }

                // Unary methods (0 args, result = same type)
                "negate" | "not" | "bootstrap" | "pack_into" => {
                    let op = method_op(&mc.method)?;
                    let tmp = ctx.temp();
                    let ti = format_ident!("{}", tmp);
                    ctx.stmts.push(
                        quote! { let #ti = __gb.add_op(#op, #recv_tid, #recv_tok, 0xFFFFu16); },
                    );
                    ctx.vars.insert(tmp.clone(), recv_tid);
                    Ok((quote! { #ti }, recv_tid))
                }

                // Unary methods (0 args, result = EBool)
                "to_boolean" => {
                    let op = method_op(&mc.method)?;
                    let tmp = ctx.temp();
                    let ti = format_ident!("{}", tmp);
                    ctx.stmts
                        .push(quote! { let #ti = __gb.add_op(#op, 0u8, #recv_tok, 0xFFFFu16); });
                    ctx.vars.insert(tmp.clone(), 0);
                    Ok((quote! { #ti }, 0u8))
                }

                // Ternary methods (2 args: a, b; receiver = condition/mask)
                "blend" | "select_scalar" => {
                    if mc.args.len() != 2 {
                        return Err(syn::Error::new_spanned(
                            &mc.method,
                            format!("`{}` needs 2 args", mc.method),
                        ));
                    }
                    let op = method_op(&mc.method)?;
                    let (a_tok, a_tid) = expr(&mc.args[0], ctx)?;
                    let (b_tok, _) = expr(&mc.args[1], ctx)?;
                    let tmp = ctx.temp();
                    let ti = format_ident!("{}", tmp);
                    ctx.stmts.push(
                        quote! { let #ti = __gb.add_ternary_op(#op, #a_tid, #recv_tok, #a_tok, #b_tok); },
                    );
                    ctx.vars.insert(tmp.clone(), a_tid);
                    Ok((quote! { #ti }, a_tid))
                }

                // Binary methods (1 arg) — default for all other ops
                // Auto-promotes to scalar variant when receiver=vector, arg=scalar.
                _ => {
                    let base_op = method_op(&mc.method)?;
                    if mc.args.is_empty() {
                        // 0-arg unary: treat as unary op (result = same type)
                        let tmp = ctx.temp();
                        let ti = format_ident!("{}", tmp);
                        ctx.stmts.push(
                            quote! { let #ti = __gb.add_op(#base_op, #recv_tid, #recv_tok, 0xFFFFu16); },
                        );
                        ctx.vars.insert(tmp.clone(), recv_tid);
                        return Ok((quote! { #ti }, recv_tid));
                    }
                    let (arg_tok, arg_tid) = expr(&mc.args[0], ctx)?;
                    let op = maybe_scalar_op(base_op, recv_tid, arg_tid);
                    let tmp = ctx.temp();
                    let ti = format_ident!("{}", tmp);
                    ctx.stmts.push(
                        quote! { let #ti = __gb.add_op(#op, #recv_tid, #recv_tok, #arg_tok); },
                    );
                    ctx.vars.insert(tmp.clone(), recv_tid);
                    Ok((quote! { #ti }, recv_tid))
                }
            }
        }

        // a + b, a >= b, etc.
        // Auto-promotes to scalar variant when left=vector, right=scalar.
        // Auto-promotes integer/bool literals to constant nodes matching the other operand's type.
        Expr::Binary(bin) => {
            let (l_tok, l_tid) = expr(&bin.left, ctx)?;
            let (r_tok, r_tid) = if let Ok(val) = parse_const_value(&bin.right) {
                // Right operand is a bare literal — auto-create constant with left's type
                let tmp = ctx.temp();
                let ti = format_ident!("{}", tmp);
                ctx.stmts
                    .push(quote! { let #ti = __gb.add_constant(#l_tid, #val); });
                ctx.vars.insert(tmp.clone(), l_tid);
                (quote! { #ti }, l_tid)
            } else {
                expr(&bin.right, ctx)?
            };
            let base_op = binop(&bin.op)?;
            let op = maybe_scalar_op(base_op, l_tid, r_tid);
            let tmp = ctx.temp();
            let ti = format_ident!("{}", tmp);
            ctx.stmts
                .push(quote! { let #ti = __gb.add_op(#op, #l_tid, #l_tok, #r_tok); });
            ctx.vars.insert(tmp.clone(), l_tid);
            Ok((quote! { #ti }, l_tid))
        }

        // -a, !a
        Expr::Unary(un) => {
            let (operand_tok, o_tid) = expr(&un.expr, ctx)?;
            let op = unop(&un.op)?;
            let tmp = ctx.temp();
            let ti = format_ident!("{}", tmp);
            ctx.stmts
                .push(quote! { let #ti = __gb.add_op(#op, #o_tid, #operand_tok, 0xFFFFu16); });
            ctx.vars.insert(tmp.clone(), o_tid);
            Ok((quote! { #ti }, o_tid))
        }

        // if cond { a } else { b } -> Select
        Expr::If(eif) => {
            let (cond_tok, _) = expr(&eif.cond, ctx)?;
            let true_e = block_expr(&eif.then_branch)?;
            let (true_tok, true_tid) = expr(true_e, ctx)?;
            let else_branch = eif
                .else_branch
                .as_ref()
                .ok_or_else(|| syn::Error::new_spanned(eif, "else required"))?;
            let false_e = match &*else_branch.1 {
                Expr::Block(b) => block_expr(&b.block)?,
                other => other,
            };
            let (false_tok, _) = expr(false_e, ctx)?;
            let tmp = ctx.temp();
            let ti = format_ident!("{}", tmp);
            ctx.stmts.push(
                quote! { let #ti = __gb.add_ternary_op(60u8, #true_tid, #cond_tok, #true_tok, #false_tok); },
            );
            ctx.vars.insert(tmp.clone(), true_tid);
            Ok((quote! { #ti }, true_tid))
        }

        // Type::from(v), Type::from_elements([...]), Type::splat(v) -> Constant node
        Expr::Call(call) => {
            let (type_name, method_name) = match &*call.func {
                Expr::Path(p) => {
                    let segs = &p.path.segments;
                    if segs.len() == 2 {
                        (segs[0].ident.to_string(), segs[1].ident.to_string())
                    } else {
                        return Err(syn::Error::new_spanned(
                            &call.func,
                            "expected Type::from(v), Type::from_elements([...]), or Type::splat(v)",
                        ));
                    }
                }
                _ => {
                    return Err(syn::Error::new_spanned(
                        &call.func,
                        "unsupported call expression",
                    ))
                }
            };

            let tid = type_id(&type_name).ok_or_else(|| {
                syn::Error::new_spanned(&call.func, format!("unknown FHE type: {type_name}"))
            })?;

            if call.args.len() != 1 {
                return Err(syn::Error::new_spanned(
                    &call.func,
                    format!("`{method_name}()` takes exactly 1 argument"),
                ));
            }

            let arg = &call.args[0];
            let tmp = ctx.temp();
            let ti = format_ident!("{}", tmp);

            match method_name.as_str() {
                "from" => match parse_const_value(arg) {
                    Ok(value) => {
                        ctx.stmts
                            .push(quote! { let #ti = __gb.add_constant(#tid, #value); });
                    }
                    Err(_) => {
                        let bytes = parse_const_bytes(arg)?;
                        ctx.stmts
                            .push(quote! { let #ti = __gb.add_constant_bytes(#tid, &#bytes); });
                    }
                },
                "from_elements" => {
                    // from_elements([1u32, 2, 3, ...]) — elements as scalars (<=16B)
                    // from_elements([[0u8; 64], [1u8; 64], ...]) — elements as byte arrays (>16B)
                    let arr = parse_const_bytes(arg)?;
                    let elem_size = vec_element_size(tid);
                    if elem_size == 0 {
                        return Err(syn::Error::new_spanned(
                            &call.func,
                            "from_elements is only for arithmetic vector types",
                        ));
                    }
                    if elem_size <= 16 {
                        // Scalar elements: .to_le_bytes()
                        ctx.stmts.push(quote! {
                            let #ti = {
                                let __elems = #arr;
                                let mut __bytes = Vec::new();
                                for __e in __elems.iter() {
                                    __bytes.extend_from_slice(&__e.to_le_bytes());
                                }
                                __gb.add_constant_bytes(#tid, &__bytes)
                            };
                        });
                    } else {
                        // Byte-array elements: each element is [u8; elem_size]
                        let es = elem_size;
                        ctx.stmts.push(quote! {
                            let #ti = {
                                let __elems = #arr;
                                let mut __bytes = Vec::new();
                                for __e in __elems.iter() {
                                    assert_eq!(__e.len(), #es, "element must be {} bytes", #es);
                                    __bytes.extend_from_slice(__e);
                                }
                                __gb.add_constant_bytes(#tid, &__bytes)
                            };
                        });
                    }
                }
                "splat" => {
                    // splat(42u32) — scalar value (elem <= 16B)
                    // splat([0u8; 64]) — byte array value (elem > 16B)
                    let elem_size = vec_element_size(tid);
                    if elem_size == 0 {
                        // Non-vector: splat = from
                        let value = parse_const_value(arg)?;
                        ctx.stmts
                            .push(quote! { let #ti = __gb.add_constant(#tid, #value); });
                    } else if elem_size <= 16 {
                        // Small elements: scalar splat
                        let value = parse_const_value(arg)?;
                        let num_elems = vec_num_elements(tid);
                        let es = elem_size;
                        ctx.stmts.push(quote! {
                            let #ti = {
                                let __val_bytes = (#value as u128).to_le_bytes();
                                let mut __bytes = Vec::new();
                                for _ in 0..#num_elems {
                                    __bytes.extend_from_slice(&__val_bytes[..#es]);
                                }
                                __gb.add_constant_bytes(#tid, &__bytes)
                            };
                        });
                    } else {
                        // Large elements: byte array splat
                        let bytes = parse_const_bytes(arg)?;
                        let num_elems = vec_num_elements(tid);
                        let es = elem_size;
                        ctx.stmts.push(quote! {
                            let #ti = {
                                let __val: [u8; #es] = #bytes;
                                let mut __bytes = Vec::new();
                                for _ in 0..#num_elems {
                                    __bytes.extend_from_slice(&__val);
                                }
                                __gb.add_constant_bytes(#tid, &__bytes)
                            };
                        });
                    }
                }
                // Type::into(val) — conversion to target type (scalar or vector)
                "into" => {
                    // val must be an encrypted variable; tid is the TARGET type
                    let (val_tok, _val_tid) = expr(arg, ctx)?;
                    ctx.stmts
                        .push(quote! { let #ti = __gb.add_op(82u8, #tid, #val_tok, 0xFFFFu16); });
                }
                _ => {
                    return Err(syn::Error::new_spanned(
                        &call.func,
                        format!("unsupported constructor `{method_name}`; use from, from_elements, splat, or into"),
                    ));
                }
            }

            ctx.vars.insert(tmp.clone(), tid);
            Ok((quote! { #ti }, tid))
        }

        _ => Err(syn::Error::new_spanned(e, "unsupported expression")),
    }
}

// ── Output emission ──

pub fn emit_outputs(e: &Expr, ctx: &mut Ctx) -> Result<(), syn::Error> {
    match e {
        Expr::Tuple(t) => {
            for elem in &t.elems {
                let (tok, tid) = expr(elem, ctx)?;
                ctx.stmts.push(quote! { __gb.add_output(#tid, #tok); });
            }
            Ok(())
        }
        _ => {
            let (tok, tid) = expr(e, ctx)?;
            ctx.stmts.push(quote! { __gb.add_output(#tid, #tok); });
            Ok(())
        }
    }
}

// ── Helpers ──

pub fn pat_ident(pat: &Pat) -> Result<String, syn::Error> {
    match pat {
        Pat::Ident(pi) => Ok(pi.ident.to_string()),
        Pat::Type(pt) => pat_ident(&pt.pat),
        _ => Err(syn::Error::new_spanned(pat, "expected identifier")),
    }
}

pub fn path_ident(p: &syn::ExprPath) -> Result<String, syn::Error> {
    Ok(p.path
        .segments
        .last()
        .ok_or_else(|| syn::Error::new_spanned(p, "empty path"))?
        .ident
        .to_string())
}

fn block_expr(block: &syn::Block) -> Result<&Expr, syn::Error> {
    match block.stmts.last() {
        Some(Stmt::Expr(e, None)) => Ok(e),
        _ => Err(syn::Error::new_spanned(
            block,
            "branch must be a single expression",
        )),
    }
}

pub fn resolve_type(ty: &Type) -> Result<u8, syn::Error> {
    match ty {
        Type::Path(tp) => {
            let name = tp
                .path
                .segments
                .last()
                .ok_or_else(|| syn::Error::new_spanned(ty, "empty type"))?
                .ident
                .to_string();
            type_id(&name)
                .ok_or_else(|| syn::Error::new_spanned(ty, format!("unknown FHE type: {name}")))
        }
        _ => Err(syn::Error::new_spanned(ty, "expected type path")),
    }
}

pub fn resolve_type_name(ty: &Type) -> Result<String, syn::Error> {
    match ty {
        Type::Path(tp) => Ok(tp
            .path
            .segments
            .last()
            .ok_or_else(|| syn::Error::new_spanned(ty, "empty type"))?
            .ident
            .to_string()),
        _ => Err(syn::Error::new_spanned(ty, "expected type path")),
    }
}

/// Parse the return type into a list of type name strings.
/// Rejects plaintext types in return position — outputs must be encrypted.
pub fn parse_return_types(ret: &syn::ReturnType) -> Result<Vec<String>, syn::Error> {
    match ret {
        syn::ReturnType::Default => Err(syn::Error::new(
            proc_macro2::Span::call_site(),
            "encrypt_fn_graph must have a return type",
        )),
        syn::ReturnType::Type(_, ty) => {
            let names = match ty.as_ref() {
                Type::Tuple(t) => t
                    .elems
                    .iter()
                    .map(resolve_type_name)
                    .collect::<Result<Vec<_>, _>>()?,
                _ => vec![resolve_type_name(ty)?],
            };
            for name in &names {
                if is_plaintext_type(name) {
                    return Err(syn::Error::new_spanned(
                        ty,
                        format!("encrypt_fn_graph outputs must be encrypted types, not plaintext (`{name}`)")
                    ));
                }
            }
            Ok(names)
        }
    }
}

/// Parse a byte array expression: `[0xFFu8; 32]` or `[1, 2, 3, ...]`.
/// Returns a token stream that evaluates to a `[u8; N]` or `Vec<u8>`.
fn parse_const_bytes(e: &Expr) -> Result<proc_macro2::TokenStream, syn::Error> {
    match e {
        // [expr; N] repeat syntax, e.g. [0u8; 32]
        Expr::Repeat(rep) => {
            let val = &rep.expr;
            let len = &rep.len;
            Ok(quote! { [#val; #len] })
        }
        // [a, b, c, ...] explicit array
        Expr::Array(arr) => {
            let elems = &arr.elems;
            Ok(quote! { [#elems] })
        }
        // Reference to a byte slice: &[...] or &arr
        Expr::Reference(r) => parse_const_bytes(&r.expr),
        _ => Err(syn::Error::new_spanned(
            e,
            "expected integer literal, bool, or byte array ([0u8; N] / [a, b, ...])",
        )),
    }
}

fn parse_const_value(e: &Expr) -> Result<u128, syn::Error> {
    match e {
        Expr::Lit(lit) => match &lit.lit {
            syn::Lit::Int(i) => i
                .base10_parse::<u128>()
                .map_err(|_| syn::Error::new_spanned(i, "integer too large for u128")),
            syn::Lit::Bool(b) => Ok(b.value as u128),
            _ => Err(syn::Error::new_spanned(
                &lit.lit,
                "expected integer or bool literal",
            )),
        },
        _ => Err(syn::Error::new_spanned(e, "expected literal value")),
    }
}

/// Element byte size for arithmetic vector types. Returns 0 for non-vector types.
fn vec_element_size(tid: u8) -> usize {
    match tid {
        32 => 1,    // EUint8Vector:     u8
        33 => 2,    // EUint16Vector:    u16
        34 => 4,    // EUint32Vector:    u32
        35 => 8,    // EUint64Vector:    u64
        36 => 16,   // EUint128Vector:   u128
        37 => 32,   // EUint256Vector:   256-bit
        38 => 64,   // EUint512Vector:   512-bit
        39 => 128,  // EUint1024Vector
        40 => 256,  // EUint2048Vector
        41 => 512,  // EUint4096Vector
        42 => 1024, // EUint8192Vector
        43 => 2048, // EUint16384Vector
        44 => 4096, // EUint32768Vector
        _ => 0,
    }
}

/// Number of elements for arithmetic vector types. All are 65536 total bits.
fn vec_num_elements(tid: u8) -> usize {
    match tid {
        32 => 8192, // EUint8Vector
        33 => 4096, // EUint16Vector
        34 => 2048, // EUint32Vector
        35 => 1024, // EUint64Vector
        36 => 512,  // EUint128Vector
        37 => 256,  // EUint256Vector
        38 => 128,  // EUint512Vector
        39 => 64,   // EUint1024Vector
        40 => 32,   // EUint2048Vector
        41 => 16,   // EUint4096Vector
        42 => 8,    // EUint8192Vector
        43 => 4,    // EUint16384Vector
        44 => 2,    // EUint32768Vector
        _ => 0,
    }
}

pub fn type_id(name: &str) -> Option<u8> {
    match name {
        "EBool" => Some(0),
        "EUint8" => Some(1),
        "EUint16" => Some(2),
        "EUint32" => Some(3),
        "EUint64" => Some(4),
        "EUint128" => Some(5),
        "EUint256" => Some(6),
        "EAddress" => Some(7),
        "EUint512" => Some(8),
        "EUint1024" => Some(9),
        "EUint2048" => Some(10),
        "EUint4096" => Some(11),
        "EUint8192" => Some(12),
        "EUint16384" => Some(13),
        "EUint32768" => Some(14),
        "EUint65536" => Some(15),
        "E2BitVector" => Some(16),
        "E4BitVector" => Some(17),
        "E8BitVector" => Some(18),
        "E16BitVector" => Some(19),
        "E32BitVector" => Some(20),
        "E64BitVector" => Some(21),
        "E128BitVector" => Some(22),
        "E256BitVector" => Some(23),
        "E512BitVector" => Some(24),
        "E1024BitVector" => Some(25),
        "E2048BitVector" => Some(26),
        "E4096BitVector" => Some(27),
        "E8192BitVector" => Some(28),
        "E16384BitVector" => Some(29),
        "E32768BitVector" => Some(30),
        "E65536BitVector" => Some(31),
        "EUint8Vector" => Some(32),
        "EUint16Vector" => Some(33),
        "EUint32Vector" => Some(34),
        "EUint64Vector" => Some(35),
        "EUint128Vector" => Some(36),
        "EUint256Vector" => Some(37),
        "EUint512Vector" => Some(38),
        "EUint1024Vector" => Some(39),
        "EUint2048Vector" => Some(40),
        "EUint4096Vector" => Some(41),
        "EUint8192Vector" => Some(42),
        "EUint16384Vector" => Some(43),
        "EUint32768Vector" => Some(44),
        // Plaintext types — same FHE IDs as encrypted counterparts
        "PBool" => Some(0),
        "PUint8" => Some(1),
        "PUint16" => Some(2),
        "PUint32" => Some(3),
        "PUint64" => Some(4),
        "PUint128" => Some(5),
        "PUint256" => Some(6),
        "PAddress" => Some(7),
        "PUint512" => Some(8),
        "PUint1024" => Some(9),
        "PUint2048" => Some(10),
        "PUint4096" => Some(11),
        "PUint8192" => Some(12),
        "PUint16384" => Some(13),
        "PUint32768" => Some(14),
        "PUint65536" => Some(15),
        "P2BitVector" => Some(16),
        "P4BitVector" => Some(17),
        "P8BitVector" => Some(18),
        "P16BitVector" => Some(19),
        "P32BitVector" => Some(20),
        "P64BitVector" => Some(21),
        "P128BitVector" => Some(22),
        "P256BitVector" => Some(23),
        "P512BitVector" => Some(24),
        "P1024BitVector" => Some(25),
        "P2048BitVector" => Some(26),
        "P4096BitVector" => Some(27),
        "P8192BitVector" => Some(28),
        "P16384BitVector" => Some(29),
        "P32768BitVector" => Some(30),
        "P65536BitVector" => Some(31),
        "PUint8Vector" => Some(32),
        "PUint16Vector" => Some(33),
        "PUint32Vector" => Some(34),
        "PUint64Vector" => Some(35),
        "PUint128Vector" => Some(36),
        "PUint256Vector" => Some(37),
        "PUint512Vector" => Some(38),
        "PUint1024Vector" => Some(39),
        "PUint2048Vector" => Some(40),
        "PUint4096Vector" => Some(41),
        "PUint8192Vector" => Some(42),
        "PUint16384Vector" => Some(43),
        "PUint32768Vector" => Some(44),
        _ => None,
    }
}

fn method_op(ident: &syn::Ident) -> Result<u8, syn::Error> {
    match ident.to_string().as_str() {
        // Arithmetic (0-8)
        "add" => Ok(0),
        "multiply" => Ok(1),
        "negate" => Ok(2),
        "subtract" => Ok(3),
        "divide" => Ok(4),
        "modulo" => Ok(5),
        "min" => Ok(6),
        "max" => Ok(7),
        "blend" => Ok(8),
        // Boolean (20-29)
        "xor" => Ok(20),
        "and" => Ok(21),
        "not" => Ok(22),
        "or" => Ok(23),
        "nor" => Ok(24),
        "nand" => Ok(25),
        "shift_left" => Ok(26),
        "shift_right" => Ok(27),
        "rotate_left" => Ok(28),
        "rotate_right" => Ok(29),
        // Comparison (40-45)
        "is_less_than" => Ok(40),
        "is_equal" => Ok(41),
        "is_not_equal" => Ok(42),
        "is_greater_than" => Ok(43),
        "is_greater_or_equal" => Ok(44),
        "is_less_or_equal" => Ok(45),
        // Conditional (60-61)
        "select_scalar" => Ok(61),
        // Conversion (80-86)
        "extract_lsbs" => Ok(80),
        "pack_into" => Ok(81),
        "extract_msbs" => Ok(84),
        "to_boolean" => Ok(83),
        "bootstrap" => Ok(85),
        "thin_bootstrap" => Ok(86),
        // Vector (90-95)
        "gather" => Ok(90),
        "scatter" => Ok(91),
        "assign" => Ok(92),
        "assign_scalars" => Ok(93),
        "copy" => Ok(94),
        "get" => Ok(95),
        _ => Err(syn::Error::new_spanned(
            ident,
            format!("unsupported FHE method `{ident}`"),
        )),
    }
}

/// If left operand is a vector (type 16-44) and right is a scalar (0-15),
/// return the scalar variant of the operation. Otherwise return the base op.
fn maybe_scalar_op(base_op: u8, left_tid: u8, right_tid: u8) -> u8 {
    if left_tid >= 16 && right_tid <= 15 {
        match base_op {
            0 => 9,   // Add -> AddScalar
            1 => 10,  // Multiply -> MultiplyScalar
            3 => 11,  // Subtract -> SubtractScalar
            4 => 12,  // Divide -> DivideScalar
            5 => 13,  // Modulo -> ModuloScalar
            6 => 14,  // Min -> MinScalar
            7 => 15,  // Max -> MaxScalar
            20 => 32, // Xor -> XorScalar
            21 => 30, // And -> AndScalar
            23 => 31, // Or -> OrScalar
            40 => 46, // IsLessThan -> IsLessThanScalar
            41 => 47, // IsEqual -> IsEqualScalar
            42 => 48, // IsNotEqual -> IsNotEqualScalar
            43 => 49, // IsGreaterThan -> IsGreaterThanScalar
            44 => 50, // IsGreaterOrEqual -> IsGreaterOrEqualScalar
            45 => 51, // IsLessOrEqual -> IsLessOrEqualScalar
            _ => base_op,
        }
    } else {
        base_op
    }
}

fn binop(op: &BinOp) -> Result<u8, syn::Error> {
    match op {
        BinOp::Add(_) => Ok(0),
        BinOp::Sub(_) => Ok(3),
        BinOp::Mul(_) => Ok(1),
        BinOp::Div(_) => Ok(4),
        BinOp::Rem(_) => Ok(5),
        BinOp::BitAnd(_) => Ok(21),
        BinOp::BitOr(_) => Ok(23),
        BinOp::BitXor(_) => Ok(20),
        BinOp::Shl(_) => Ok(26),
        BinOp::Shr(_) => Ok(27),
        BinOp::Eq(_) => Ok(41),
        BinOp::Ne(_) => Ok(42),
        BinOp::Gt(_) => Ok(43),
        BinOp::Ge(_) => Ok(44),
        BinOp::Lt(_) => Ok(40),
        BinOp::Le(_) => Ok(45),
        _ => Err(syn::Error::new_spanned(op, "unsupported operator")),
    }
}

fn unop(op: &UnOp) -> Result<u8, syn::Error> {
    match op {
        UnOp::Neg(_) => Ok(2),
        UnOp::Not(_) => Ok(22),
        _ => Err(syn::Error::new_spanned(op, "unsupported unary operator")),
    }
}

pub fn is_plaintext_type(name: &str) -> bool {
    name.starts_with('P') && type_id(name).is_some()
}
