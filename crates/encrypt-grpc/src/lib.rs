// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Chain-agnostic gRPC types for the Encrypt executor service.
//!
//! Generated from `proto/encrypt_service.proto`. Provides both client and
//! server types for the `EncryptService` gRPC API.
//!
//! # Client usage
//!
//! ```ignore
//! use encrypt_grpc::encrypt_service_client::EncryptServiceClient;
//! use encrypt_grpc::{Chain, CreateInputRequest};
//!
//! let mut client = EncryptServiceClient::connect("https://pre-alpha-dev-1.encrypt.ika-network.net:443").await?;
//! let resp = client.create_input(CreateInputRequest {
//!     chain: Chain::Solana.into(),
//!     encrypted_ciphertext: ciphertext_bytes,
//!     proof: vec![],
//!     fhe_type: 0,
//!     authorized: address_bytes.to_vec(),
//!     network_encryption_public_key: key_bytes.to_vec(),
//! }).await?;
//! ```
//!
//! # Server usage
//!
//! ```ignore
//! use encrypt_grpc::encrypt_service_server::{EncryptService, EncryptServiceServer};
//! ```

include!(concat!(env!("OUT_DIR"), "/encrypt.v1.rs"));
