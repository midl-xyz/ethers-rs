use super::{eip2718::TypedTransaction, eip2930::AccessList, normalize_v};
use crate::types::{
    transaction::request::TransactionRequest, Bytes, Signature, SignatureError, Transaction, H256,
    U256, U64,
};
use rlp::{Decodable, RlpStream};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const NUM_MIDL_FIELDS: usize = 11;
const PUBLIC_KEY_LENGTH: usize = 32;
pub const MIDL_DEFAULT_GAS_LIMIT: u64 = 10_000_000;

#[inline]
fn zero_public_key() -> Bytes {
    Bytes::from(vec![0u8; PUBLIC_KEY_LENGTH])
}

#[inline]
fn is_zero_bytes(bytes: &Bytes) -> bool {
    bytes.iter().all(|b| *b == 0)
}

/// An error involving a Midl transaction request.
#[derive(Debug, Error)]
pub enum MidlRequestError {
    /// When decoding a transaction request from RLP
    #[error(transparent)]
    DecodingError(#[from] rlp::DecoderError),
    /// When recovering the address from a signature
    #[error(transparent)]
    RecoveryError(#[from] SignatureError),
}

/// Midl (type 0x07) transaction.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct MidlTransactionRequest {
    pub tx: TransactionRequest,
    pub btc_tx_hash: Option<H256>,
    pub public_key: Option<Bytes>,
    pub btc_address_byte: Option<U256>,
    pub access_list: AccessList,
}

// TransactionRequest has `chain_id` marked `#[serde(skip_serializing)]` globally.
// For Midl transactions, we *do* want `chainId` to roundtrip in JSON (and other serde formats),
// so we provide a custom serde implementation that includes it.
#[derive(Serialize, Deserialize)]
struct TransactionRequestSerde {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<crate::types::Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<crate::types::NameOrAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas: Option<U256>,
    #[serde(rename = "gasPrice")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_price: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Bytes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<U256>,
    #[serde(default, rename = "chainId", skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<U64>,

    /////////////////  Celo-specific transaction fields /////////////////
    #[cfg(feature = "celo")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_currency: Option<crate::types::Address>,
    #[cfg(feature = "celo")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_fee_recipient: Option<crate::types::Address>,
    #[cfg(feature = "celo")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_fee: Option<U256>,
}

impl From<&TransactionRequest> for TransactionRequestSerde {
    fn from(tx: &TransactionRequest) -> Self {
        Self {
            from: tx.from,
            to: tx.to.clone(),
            gas: tx.gas,
            gas_price: tx.gas_price,
            value: tx.value,
            data: tx.data.clone(),
            nonce: tx.nonce,
            chain_id: tx.chain_id,
            #[cfg(feature = "celo")]
            fee_currency: tx.fee_currency,
            #[cfg(feature = "celo")]
            gateway_fee_recipient: tx.gateway_fee_recipient,
            #[cfg(feature = "celo")]
            gateway_fee: tx.gateway_fee,
        }
    }
}

impl From<TransactionRequestSerde> for TransactionRequest {
    fn from(tx: TransactionRequestSerde) -> Self {
        Self {
            from: tx.from,
            to: tx.to,
            gas: tx.gas,
            gas_price: tx.gas_price,
            value: tx.value,
            data: tx.data,
            nonce: tx.nonce,
            chain_id: tx.chain_id,
            #[cfg(feature = "celo")]
            fee_currency: tx.fee_currency,
            #[cfg(feature = "celo")]
            gateway_fee_recipient: tx.gateway_fee_recipient,
            #[cfg(feature = "celo")]
            gateway_fee: tx.gateway_fee,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct MidlTransactionRequestSerde {
    #[serde(flatten)]
    pub tx: TransactionRequestSerde,
    #[serde(rename = "btcTxHash", default, skip_serializing_if = "Option::is_none")]
    pub btc_tx_hash: Option<H256>,
    #[serde(rename = "publicKey", default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<Bytes>,
    #[serde(rename = "btcAddressByte", default, skip_serializing_if = "Option::is_none")]
    pub btc_address_byte: Option<U256>,
    #[serde(default)]
    pub access_list: AccessList,
}

impl Serialize for MidlTransactionRequest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        MidlTransactionRequestSerde {
            tx: (&self.tx).into(),
            btc_tx_hash: self.btc_tx_hash,
            public_key: self.public_key.clone(),
            btc_address_byte: self.btc_address_byte,
            access_list: self.access_list.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MidlTransactionRequest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let de = MidlTransactionRequestSerde::deserialize(deserializer)?;
        Ok(Self {
            tx: de.tx.into(),
            btc_tx_hash: de.btc_tx_hash,
            public_key: de.public_key,
            btc_address_byte: de.btc_address_byte,
            access_list: de.access_list,
        })
    }
}

impl MidlTransactionRequest {
    pub fn new(tx: TransactionRequest) -> Self {
        Self { tx, ..Default::default() }
    }

    pub fn with_access_list(mut self, access_list: impl Into<AccessList>) -> Self {
        self.access_list = access_list.into();
        self
    }

    pub fn with_btc_tx_hash(mut self, btc_tx_hash: H256) -> Self {
        self.btc_tx_hash = Some(btc_tx_hash);
        self
    }

    pub fn with_public_key(mut self, public_key: Bytes) -> Self {
        self.public_key = Some(public_key);
        self
    }

    pub fn with_btc_address_byte<T: Into<U256>>(mut self, byte: T) -> Self {
        self.btc_address_byte = Some(byte.into());
        self
    }

    fn normalized_gas(&self) -> U256 {
        self.tx.gas.unwrap_or_else(|| U256::from(MIDL_DEFAULT_GAS_LIMIT))
    }

    fn normalized_btc_tx_hash(&self) -> H256 {
        self.btc_tx_hash.unwrap_or_default()
    }

    fn normalized_public_key(&self) -> Bytes {
        self.public_key.clone().unwrap_or_else(zero_public_key)
    }

    fn normalized_btc_address_byte(&self) -> U256 {
        self.btc_address_byte.unwrap_or_default()
    }

    fn normalized_tx(&self) -> TransactionRequest {
        let mut tx = self.tx.clone();
        if tx.gas.is_none() {
            tx.gas = Some(self.normalized_gas());
        }
        if tx.gas_price.is_none() {
            tx.gas_price = Some(U256::zero());
        }
        tx
    }

    pub fn rlp(&self) -> Bytes {
        let tx = self.normalized_tx();
        let mut rlp = RlpStream::new();
        rlp.begin_list(NUM_MIDL_FIELDS);

        let chain_id = tx.chain_id.unwrap_or_else(U64::one);
        rlp.append(&chain_id);
        tx.rlp_base(&mut rlp);
        rlp.append(&self.normalized_btc_tx_hash());
        rlp.append(&self.normalized_public_key().as_ref());
        rlp.append(&self.normalized_btc_address_byte());
        rlp.append(&self.access_list);

        rlp.out().freeze().into()
    }

    pub fn rlp_signed(&self, signature: &Signature) -> Bytes {
        let tx = self.normalized_tx();
        let mut rlp = RlpStream::new();
        rlp.begin_list(NUM_MIDL_FIELDS + 3);

        let chain_id = tx.chain_id.unwrap_or_else(U64::one);
        rlp.append(&chain_id);
        tx.rlp_base(&mut rlp);
        rlp.append(&self.normalized_btc_tx_hash());
        rlp.append(&self.normalized_public_key().as_ref());
        rlp.append(&self.normalized_btc_address_byte());
        rlp.append(&self.access_list);

        let v = normalize_v(signature.v, chain_id);
        rlp.append(&v);
        rlp.append(&signature.r);
        rlp.append(&signature.s);

        rlp.out().freeze().into()
    }

    fn decode_base_rlp(rlp: &rlp::Rlp, offset: &mut usize) -> Result<Self, rlp::DecoderError> {
        let chain_id: u64 = rlp.val_at(*offset)?;
        *offset += 1;

        let mut request = TransactionRequest::decode_unsigned_rlp_base(rlp, offset)?;
        request.chain_id = Some(U64::from(chain_id));

        let btc_tx_hash: H256 = rlp.val_at(*offset)?;
        *offset += 1;

        let pk_rlp = rlp::Rlp::new(rlp.at(*offset)?.as_raw()).data()?.to_vec();
        let public_key_bytes = Bytes::from(pk_rlp);
        *offset += 1;

        let btc_address_byte: U256 = rlp.val_at(*offset)?;
        *offset += 1;

        let al = rlp::Rlp::new(rlp.at(*offset)?.as_raw()).data()?;
        let access_list = match al.len() {
            0 => AccessList(vec![]),
            _ => rlp.val_at(*offset)?,
        };
        *offset += 1;

        Ok(Self {
            tx: request,
            btc_tx_hash: (btc_tx_hash != H256::zero()).then_some(btc_tx_hash),
            public_key: (!is_zero_bytes(&public_key_bytes)).then_some(public_key_bytes),
            btc_address_byte: (!btc_address_byte.is_zero()).then_some(btc_address_byte),
            access_list,
        })
    }

    pub fn decode_signed_rlp(rlp: &rlp::Rlp) -> Result<(Self, Signature), MidlRequestError> {
        let mut offset = 0;
        let mut txn = Self::decode_base_rlp(rlp, &mut offset)?;

        let v = rlp.val_at(offset)?;
        offset += 1;
        let r = rlp.val_at(offset)?;
        offset += 1;
        let s = rlp.val_at(offset)?;

        let sig = Signature { r, s, v };
        txn.tx.from = Some(sig.recover(TypedTransaction::Midl(txn.clone()).sighash())?);
        Ok((txn, sig))
    }
}

impl Decodable for MidlTransactionRequest {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        Self::decode_base_rlp(rlp, &mut 0)
    }
}

impl From<&Transaction> for MidlTransactionRequest {
    fn from(tx: &Transaction) -> Self {
        let access_list = tx.access_list.clone().unwrap_or_else(|| AccessList(vec![]));
        Self {
            tx: tx.into(),
            btc_tx_hash: tx.btc_tx_hash,
            public_key: tx.public_key.clone(),
            btc_address_byte: tx.btc_address_byte,
            access_list,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Address, U256};

    #[test]
    fn serde_midl_transaction() {
        let request = TransactionRequest::new()
            .chain_id(1u64)
            .to(Address::zero())
            .gas(21_000)
            .gas_price(1)
            .value(U256::from(100))
            .into_midl()
            .with_btc_tx_hash(H256::repeat_byte(1))
            .with_public_key(Bytes::from(vec![1u8; PUBLIC_KEY_LENGTH]))
            .with_btc_address_byte(1u64);

        let typed: TypedTransaction = request.clone().into();
        let serialized = serde_json::to_string(&typed).unwrap();

        let deserialized: TypedTransaction = serde_json::from_str(&serialized).unwrap();
        assert_eq!(typed, deserialized);
    }

    #[test]
    fn rlp_prefix_is_type_seven() {
        let request = TransactionRequest::new()
            .chain_id(1u64)
            .to(Address::zero())
            .gas(21_000)
            .gas_price(1)
            .value(U256::from(1))
            .into_midl()
            .with_btc_tx_hash(H256::repeat_byte(2))
            .with_public_key(Bytes::from(vec![2u8; PUBLIC_KEY_LENGTH]));

        let typed: TypedTransaction = request.into();
        let encoded = typed.rlp();
        assert_eq!(encoded.as_ref()[0], 0x07);
    }
}


