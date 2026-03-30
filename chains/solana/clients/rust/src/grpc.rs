// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Solana-typed gRPC client for the Encrypt pre-alpha executor service.
//!
//! Connects to `pre-alpha-dev-1.encrypt.ika-network.net:443` (TLS).
//!
//! # Example
//!
//! ```ignore
//! use encrypt_solana_client::grpc::EncryptClient;
//! use encrypt_types::encrypted::Uint64;
//!
//! let mut client = EncryptClient::connect().await?;
//! let ct = client.create_input::<Uint64>(42u64, &program_id, &network_key).await?;
//!
//! // Batch
//! use encrypt_solana_client::grpc::TypedInput;
//! let cts = client.create_inputs(
//!     &[TypedInput::new::<Uint64>(&10u64), TypedInput::new::<Uint64>(&20u64)],
//!     &program_id, &network_key,
//! ).await?;
//!
//! // Read ciphertext off-chain
//! let result = client.read_ciphertext(&ct, &[], 1, &keypair).await?;
//! ```

use solana_pubkey::Pubkey;

use encrypt_compute::mock_crypto::MockEncryptor;
use encrypt_types::encrypted::EncryptedType;
use encrypt_types::encryptor::{Chain, EncryptResult, Encryptor, PlaintextInput};
use encrypt_types::types::FheType;

/// A typed input for batch creation. Holds serialized plaintext + fhe_type.
pub struct TypedInput {
    plaintext_bytes: Vec<u8>,
    fhe_type: FheType,
}

impl TypedInput {
    /// Create a typed input from a value.
    pub fn new<T: EncryptedType>(value: &T::DecryptedValue) -> Self
    where
        T::DecryptedValue: ToPlaintextBytes,
    {
        Self {
            plaintext_bytes: value.to_plaintext_bytes(),
            fhe_type: FheType::from_u8(T::FHE_TYPE_ID).unwrap(),
        }
    }
}

/// A raw (pre-encrypted) input.
pub struct RawInput<'a> {
    pub ciphertext_bytes: &'a [u8],
    pub fhe_type: u8,
}

/// Trait for types that can be serialized to bytes for encryption.
pub trait ToPlaintextBytes {
    fn to_plaintext_bytes(&self) -> Vec<u8>;
}

impl ToPlaintextBytes for bool {
    fn to_plaintext_bytes(&self) -> Vec<u8> {
        vec![*self as u8]
    }
}
impl ToPlaintextBytes for u8 {
    fn to_plaintext_bytes(&self) -> Vec<u8> {
        vec![*self]
    }
}
macro_rules! impl_to_plaintext_bytes {
    ($($ty:ty),*) => {
        $(
            impl ToPlaintextBytes for $ty {
                fn to_plaintext_bytes(&self) -> Vec<u8> {
                    self.to_le_bytes().to_vec()
                }
            }
        )*
    };
}
impl_to_plaintext_bytes!(u16, u32, u64, u128);

impl<const N: usize> ToPlaintextBytes for [u8; N] {
    fn to_plaintext_bytes(&self) -> Vec<u8> {
        self.to_vec()
    }
}

/// gRPC endpoint for the Encrypt pre-alpha executor.
pub const GRPC_URL: &str = "https://pre-alpha-dev-1.encrypt.ika-network.net:443";

/// Solana-typed Encrypt gRPC client with pluggable encryption.
pub struct EncryptClient<E: Encryptor> {
    inner: encrypt_grpc::encrypt_service_client::EncryptServiceClient<tonic::transport::Channel>,
    encryptor: E,
}

impl EncryptClient<MockEncryptor> {
    /// Connect to the pre-alpha endpoint with mock encryption.
    pub async fn connect() -> Result<Self, EncryptClientError> {
        let channel = tonic::transport::Channel::from_static(GRPC_URL)
            .tls_config(tonic::transport::ClientTlsConfig::new().with_native_roots())
            .map_err(EncryptClientError::Transport)?
            .connect()
            .await
            .map_err(EncryptClientError::Transport)?;
        let inner = encrypt_grpc::encrypt_service_client::EncryptServiceClient::new(channel);
        Ok(Self {
            inner,
            encryptor: MockEncryptor,
        })
    }
}

impl<E: Encryptor> EncryptClient<E> {
    /// Create a single encrypted input from a plaintext value.
    ///
    /// Type-safe: `T` determines the FHE type, `value` is the plaintext.
    /// The encryptor handles encryption + proof generation.
    pub async fn create_input<T: EncryptedType>(
        &mut self,
        value: T::DecryptedValue,
        authorized: &Pubkey,
        network_key: &[u8; 32],
    ) -> Result<Pubkey, EncryptClientError>
    where
        T::DecryptedValue: ToPlaintextBytes + Sized,
    {
        let fhe_type = FheType::from_u8(T::FHE_TYPE_ID).unwrap();
        let plaintext_bytes = value.to_plaintext_bytes();

        let EncryptResult { ciphertexts, proof } = self.encryptor.encrypt_and_prove(
            &[PlaintextInput {
                plaintext_bytes: &plaintext_bytes,
                fhe_type,
            }],
            network_key,
            Chain::Solana,
        );

        let results = self
            .submit_raw(
                &ciphertexts
                    .iter()
                    .enumerate()
                    .map(|(_, ct)| RawInput {
                        ciphertext_bytes: ct,
                        fhe_type: T::FHE_TYPE_ID,
                    })
                    .collect::<Vec<_>>(),
                &proof,
                authorized,
                network_key,
            )
            .await?;

        results
            .into_iter()
            .next()
            .ok_or(EncryptClientError::EmptyResponse)
    }

    /// Create multiple encrypted inputs from plaintext values (batch).
    ///
    /// One proof covers all inputs.
    pub async fn create_inputs(
        &mut self,
        inputs: &[TypedInput],
        authorized: &Pubkey,
        network_key: &[u8; 32],
    ) -> Result<Vec<Pubkey>, EncryptClientError> {
        let plaintext_inputs: Vec<PlaintextInput<'_>> = inputs
            .iter()
            .map(|i| PlaintextInput {
                plaintext_bytes: &i.plaintext_bytes,
                fhe_type: i.fhe_type,
            })
            .collect();

        let EncryptResult { ciphertexts, proof } =
            self.encryptor
                .encrypt_and_prove(&plaintext_inputs, network_key, Chain::Solana);

        let raw_inputs: Vec<RawInput<'_>> = ciphertexts
            .iter()
            .zip(inputs.iter())
            .map(|(ct, inp)| RawInput {
                ciphertext_bytes: ct,
                fhe_type: inp.fhe_type as u8,
            })
            .collect();

        self.submit_raw(&raw_inputs, &proof, authorized, network_key)
            .await
    }

    /// Submit pre-encrypted ciphertexts + proof directly (advanced).
    pub async fn submit_raw(
        &mut self,
        inputs: &[RawInput<'_>],
        proof: &[u8],
        authorized: &Pubkey,
        network_key: &[u8; 32],
    ) -> Result<Vec<Pubkey>, EncryptClientError> {
        let grpc_inputs: Vec<encrypt_grpc::EncryptedInput> = inputs
            .iter()
            .map(|p| encrypt_grpc::EncryptedInput {
                ciphertext_bytes: p.ciphertext_bytes.to_vec(),
                fhe_type: p.fhe_type as u32,
            })
            .collect();

        let resp = self
            .inner
            .create_input(encrypt_grpc::CreateInputRequest {
                chain: encrypt_grpc::Chain::Solana.into(),
                inputs: grpc_inputs,
                proof: proof.to_vec(),
                authorized: authorized.to_bytes().to_vec(),
                network_encryption_public_key: network_key.to_vec(),
            })
            .await
            .map_err(EncryptClientError::Rpc)?;

        let identifiers = resp.into_inner().ciphertext_identifiers;

        if identifiers.len() != inputs.len() {
            return Err(EncryptClientError::CountMismatch {
                expected: inputs.len(),
                got: identifiers.len(),
            });
        }

        identifiers
            .into_iter()
            .enumerate()
            .map(|(i, bytes)| {
                let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
                    EncryptClientError::InvalidIdentifier {
                        index: i,
                        len: v.len(),
                    }
                })?;
                Ok(Pubkey::from(arr))
            })
            .collect()
    }
}

/// Result of reading a ciphertext.
pub struct ReadCiphertextResult {
    /// Production: re-encrypted ciphertext. Mock: plaintext bytes.
    pub value: Vec<u8>,
    /// FHE type.
    pub fhe_type: FheType,
    /// On-chain digest.
    pub digest: [u8; 32],
}

impl<E: Encryptor> EncryptClient<E> {
    /// Read a ciphertext off-chain. Signs the request with the provided keypair.
    ///
    /// In mock mode: returns plaintext bytes.
    /// In production: returns ciphertext re-encrypted under `reencryption_key`.
    pub async fn read_ciphertext(
        &mut self,
        ciphertext: &Pubkey,
        reencryption_key: &[u8],
        epoch: u64,
        signer: &solana_sdk::signature::Keypair,
    ) -> Result<ReadCiphertextResult, EncryptClientError> {
        use encrypt_types::messages::ReadCiphertextMessage;
        use solana_sdk::signer::Signer;

        let msg = ReadCiphertextMessage {
            chain: 0, // Solana
            ciphertext_identifier: ciphertext.to_bytes().to_vec(),
            reencryption_key: reencryption_key.to_vec(),
            epoch,
        };
        let bcs_bytes = msg.to_bcs();

        let signature = signer.sign_message(&bcs_bytes);

        let resp = self
            .inner
            .read_ciphertext(encrypt_grpc::ReadCiphertextRequest {
                message: bcs_bytes,
                signature: signature.as_ref().to_vec(),
                signer: signer.pubkey().to_bytes().to_vec(),
            })
            .await
            .map_err(EncryptClientError::Rpc)?;

        let inner = resp.into_inner();
        let fhe_type = FheType::from_u8(inner.fhe_type as u8)
            .ok_or(EncryptClientError::InvalidIdentifier { index: 0, len: 0 })?;
        let digest: [u8; 32] = inner.digest.try_into().map_err(|v: Vec<u8>| {
            EncryptClientError::InvalidIdentifier {
                index: 0,
                len: v.len(),
            }
        })?;

        Ok(ReadCiphertextResult {
            value: inner.value,
            fhe_type,
            digest,
        })
    }
}

/// Errors from the Solana Encrypt gRPC client.
#[derive(Debug)]
pub enum EncryptClientError {
    Transport(tonic::transport::Error),
    Rpc(tonic::Status),
    EmptyResponse,
    CountMismatch { expected: usize, got: usize },
    InvalidIdentifier { index: usize, len: usize },
}

impl std::fmt::Display for EncryptClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "connection error: {e}"),
            Self::Rpc(status) => write!(f, "gRPC error: {status}"),
            Self::EmptyResponse => write!(f, "empty response from executor"),
            Self::CountMismatch { expected, got } => {
                write!(f, "expected {expected} identifiers, got {got}")
            }
            Self::InvalidIdentifier { index, len } => {
                write!(f, "identifier[{index}]: expected 32 bytes, got {len}")
            }
        }
    }
}

impl std::error::Error for EncryptClientError {}
