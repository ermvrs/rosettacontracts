use crate::utils::transaction::common::{TxKind};
use crate::utils::transaction::eip2930::{AccessListItem};
use crate::utils::traits::SpanDefault;
use crate::utils::rlp::{RLPItem, RLPHelpersTrait};
use crate::errors::{EthTransactionError, RLPError, RLPErrorTrait};

#[derive(Copy, Drop, Debug, Default, PartialEq, Serde)]
pub struct Eip1559 {
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub to: TxKind,
    pub value: u256,
    pub access_list: Span<AccessListItem>,
    pub input: Span<u8>,
}

#[generate_trait]
pub impl _impl of Eip1559Trait {
    /// Decodes the RLP-encoded fields into a TxEip1559 struct.
    ///
    /// # Arguments
    ///
    /// * `data` - A span of RLPItems containing the encoded transaction fields
    ///
    /// # Returns
    ///
    /// A Result containing either the decoded TxEip1559 struct or an EthTransactionError
    fn decode_fields(ref data: Span<RLPItem>) -> Result<Eip1559, EthTransactionError> {
        let boxed_fields = data
            .multi_pop_front::<9>()
            .ok_or(EthTransactionError::RLPError(RLPError::InputTooShort))?;
        let [
            chain_id_encoded,
            nonce_encoded,
            max_priority_fee_per_gas_encoded,
            max_fee_per_gas_encoded,
            gas_limit_encoded,
            to_encoded,
            value_encoded,
            input_encoded,
            access_list_encoded
        ] =
            (*boxed_fields)
            .unbox();

        let chain_id = chain_id_encoded.parse_u64_from_string().map_err()?;
        let nonce = nonce_encoded.parse_u64_from_string().map_err()?;
        let max_priority_fee_per_gas = max_priority_fee_per_gas_encoded
            .parse_u128_from_string()
            .map_err()?;
        let max_fee_per_gas = max_fee_per_gas_encoded.parse_u128_from_string().map_err()?;
        let gas_limit = gas_limit_encoded.parse_u64_from_string().map_err()?;
        let to = to_encoded.try_parse_address_from_string().map_err()?;
        let value = value_encoded.parse_u256_from_string().map_err()?;
        let input = input_encoded.parse_bytes_from_string().map_err()?;
        let access_list = access_list_encoded.parse_access_list().map_err()?;

        let txkind_to = match to {
            Option::Some(to) => { TxKind::Call(to) },
            Option::None => { TxKind::Create }
        };

        Result::Ok(
            Eip1559 {
                chain_id,
                nonce,
                max_priority_fee_per_gas,
                max_fee_per_gas,
                gas_limit,
                to: txkind_to,
                value,
                access_list,
                input,
            }
        )
    }
}