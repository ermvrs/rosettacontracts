use starknet::{EthAddress};
use core::byte_array::{ByteArrayTrait};
use crate::utils::transaction::eip2930::{AccessListItem, AccessListItemTrait};
use crate::utils::bytes::{ByteArrayExTrait,U8SpanExTrait};
use alexandria_encoding::rlp::{RLPItem, RLPTrait};

#[derive(Copy, Drop, Clone, PartialEq, Serde)]
pub struct Eip1559Transaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to: EthAddress,
    pub value: u256,
    pub input: Span<u8>, // u256s to u8 spans
    pub access_list: Span<AccessListItem>,
}

pub fn rlp_encode_eip1559(tx: Eip1559Transaction) -> Span<u8> {
    let chain_id = RLPItem::String(deserialize_bytes_non_zeroes(tx.chain_id.into(),8));
    let nonce = RLPItem::String(deserialize_bytes_non_zeroes(tx.nonce.into(),8));
    let max_priority_fee_per_gas = RLPItem::String(deserialize_bytes_non_zeroes(tx.max_priority_fee_per_gas.into(), 16));
    let max_fee_per_gas = RLPItem::String(deserialize_bytes_non_zeroes(tx.max_fee_per_gas.into(), 16));
    let gas_limit = RLPItem::String(deserialize_bytes_non_zeroes(tx.gas_limit.into(), 8));
    let to = RLPItem::String(deserialize_bytes(tx.to.into(), 20));
    let value = RLPItem::String(deserialize_bytes_non_zeroes(tx.value.try_into().unwrap(), 32));
    let input = RLPItem::String(tx.input);

    let mut access_arr = array![];
    let mut access_list_items = tx.access_list;
    loop {
        match access_list_items.pop_front() {
            Option::None => { break; },
            Option::Some(item) => {
                access_arr.append(item.to_rlp_items());
            }
        };
    };

    let access_list = RLPItem::List(access_arr.span());


    let mut rlp_inputs = RLPItem::List(array![chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, input, access_list].span());
    let mut encoded_tx = array![2_u8];

    encoded_tx.append_span(RLPTrait::encode(array![rlp_inputs].span()).unwrap());
    encoded_tx.span()
}

#[inline(always)]
pub fn calculate_tx_hash(encoded_tx: Span<u8>) -> u256 {
    encoded_tx.compute_keccak256_hash()
}

pub fn deserialize_bytes(value: felt252, len: usize) -> Span<u8> {
    let mut ba = Default::default();
    ba.append_word(value, len);
    ba.into_bytes()
}

pub fn deserialize_u256_span(ref value: Span<u256>) -> Span<u8> {
    let mut ba = Default::default();
    loop {
        match value.pop_front() {
            Option::None => { break; },
            Option::Some(val) => {
                let mut inner_ba = Default::default();
                inner_ba.append_word((*val).try_into().unwrap(), 32); // 32 or 16 ? U256 span is merged u256s according to directives
                ByteArrayTrait::append(ref ba, @inner_ba);
            }
        };
    };
    ba.into_bytes()
}

pub fn deserialize_bytes_non_zeroes(value: felt252, len: usize) -> Span<u8> {
    let mut ba = Default::default();
    ba.append_word(value, len);
    ba.into_bytes_without_initial_zeroes()
}


#[cfg(test)]
mod tests {
    use crate::accounts::encoding::{Eip1559Transaction, rlp_encode_eip1559, deserialize_bytes_non_zeroes};
    #[test]
    fn encode_transaction() {
        let tx = Eip1559Transaction {
            chain_id: 2933,
            nonce: 1,
            max_priority_fee_per_gas: 1000000000,
            max_fee_per_gas: 1000000000,
            gas_limit: 21000,
            to: 0x11655f4Ee2A5B66F9DCbe758e9FcdCd3eBF95eE5.try_into().unwrap(),
            value: 0x0,
            input: array![0xAB, 0xCA, 0xBC].span(), 
            access_list: array![].span()
        };

        let encoded = rlp_encode_eip1559(tx);
        assert_eq!(encoded.len(), 92);
        assert_eq!(*encoded.at(0), 0x02);
        assert_eq!(*encoded.at(1), 0xEC);
        assert_eq!(*encoded.at(2), 0x82);
        assert_eq!(*encoded.at(3), 0x0B);
        assert_eq!(*encoded.at(4), 0x75);
    }

    #[test]
    fn test_tx_bytes_decoding() {
        let value = 0x567312;

        let decoded_value: Span<u8> = deserialize_bytes_non_zeroes(value, 8);

        assert_eq!(*decoded_value.at(0), 0x56);
        assert_eq!(*decoded_value.at(1), 0x73);
        assert_eq!(*decoded_value.at(2), 0x12);
    }

    #[test]
    fn test_tx_bytes_decoding_initial_zeroes() {
        let value = 0x00567312;

        let decoded_value: Span<u8> = deserialize_bytes_non_zeroes(value, 8);

        assert_eq!(*decoded_value.at(0), 0x56);
        assert_eq!(*decoded_value.at(1), 0x73);
        assert_eq!(*decoded_value.at(2), 0x12);
    }

    #[test]
    fn test_tx_bytes_decoding_zeroes() {
        let value = 0x005673120055;

        let decoded_value: Span<u8> = deserialize_bytes_non_zeroes(value, 8);

        assert_eq!(*decoded_value.at(0), 0x56);
        assert_eq!(*decoded_value.at(1), 0x73);
        assert_eq!(*decoded_value.at(2), 0x12);
        assert_eq!(*decoded_value.at(3), 0x00);
        assert_eq!(*decoded_value.at(4), 0x55);
    }
}