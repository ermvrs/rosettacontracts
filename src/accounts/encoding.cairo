use starknet::{EthAddress};
use core::byte_array::{ByteArrayTrait};
use crate::utils::transaction::eip2930::{AccessListItem, AccessListItemTrait};
use crate::utils::bytes::{ByteArrayExTrait, U8SpanExTrait};
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

#[derive(Copy, Drop, Clone, PartialEq, Serde)]
pub struct LegacyTransaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to: EthAddress,
    pub value: u256,
    pub input: Span<u8>
}


pub fn rlp_encode_legacy(tx: LegacyTransaction) -> Span<u8> {
    // TODO: Write tests and complete tx type
    let chain_id = RLPItem::String(deserialize_bytes_non_zeroes(tx.chain_id.into(), 8));
    let nonce = RLPItem::String(deserialize_bytes_non_zeroes(tx.nonce.into(), 8));
    let gas_price = RLPItem::String(deserialize_bytes_non_zeroes(tx.gas_price.into(), 16));
    let gas_limit = RLPItem::String(deserialize_bytes_non_zeroes(tx.gas_limit.into(), 8));
    let value = RLPItem::String(deserialize_u256(tx.value));
    let to = RLPItem::String(deserialize_bytes(tx.to.into(), 20));
    let input = RLPItem::String(tx.input);
    let empty = RLPItem::String(array![].span());

    let mut rlp_inputs = RLPItem::List(
        array![nonce, gas_price, gas_limit, to, value, input, chain_id, empty, empty].span()
    );

    RLPTrait::encode(array![rlp_inputs].span()).unwrap()

}

pub fn rlp_encode_eip1559(tx: Eip1559Transaction) -> Span<u8> {
    let chain_id = RLPItem::String(deserialize_bytes_non_zeroes(tx.chain_id.into(), 8));
    let nonce = RLPItem::String(deserialize_bytes_non_zeroes(tx.nonce.into(), 8));
    let max_priority_fee_per_gas = RLPItem::String(
        deserialize_bytes_non_zeroes(tx.max_priority_fee_per_gas.into(), 16)
    );
    let max_fee_per_gas = RLPItem::String(
        deserialize_bytes_non_zeroes(tx.max_fee_per_gas.into(), 16)
    );
    let gas_limit = RLPItem::String(deserialize_bytes_non_zeroes(tx.gas_limit.into(), 8));
    let to = RLPItem::String(deserialize_bytes(tx.to.into(), 20));
    let value = RLPItem::String(deserialize_u256(tx.value));
    let input = RLPItem::String(tx.input);

    let mut access_arr = array![];
    let mut access_list_items = tx.access_list;
    loop {
        match access_list_items.pop_front() {
            Option::None => { break; },
            Option::Some(item) => { access_arr.append(item.to_rlp_items()); }
        };
    };

    let access_list = RLPItem::List(access_arr.span());

    let mut rlp_inputs = RLPItem::List(
        array![
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            input,
            access_list
        ]
            .span()
    );
    let mut encoded_tx = array![2_u8];

    encoded_tx.append_span(RLPTrait::encode(array![rlp_inputs].span()).unwrap());
    encoded_tx.span()
}

#[inline(always)]
pub fn calculate_tx_hash(encoded_tx: Span<u8>) -> u256 {
    encoded_tx.compute_keccak256_hash()
}

// Pass less than 252 bits here
pub fn bytes_from_felts(ref data: Span<felt252>) -> Span<u8> {
    let mut ba: core::byte_array::ByteArray = Default::default();
    loop {
        match data.pop_front() {
            Option::None => { break; },
            Option::Some(val) => {
                let mut bar = Default::default();
                bar.append_word(*val, 31);
                let mut non_zeroes = bar.into_bytes_without_initial_zeroes();
                ba.append(@ByteArrayExTrait::from_bytes(non_zeroes));
            }
        };
    };

    ba.into_bytes_without_initial_zeroes()
}

pub fn deserialize_bytes(value: felt252, len: usize) -> Span<u8> {
    let mut ba = Default::default();
    ba.append_word(value, len);
    ba.into_bytes()
}

pub fn deserialize_u256_with_zeroes(value: u256) -> Span<u8> {
    let mut ba: core::byte_array::ByteArray = Default::default();
    let low_bytes = deserialize_bytes(value.low.into(), 16);
    let high_bytes = deserialize_bytes(value.high.into(), 16);
    ba.append(@ByteArrayExTrait::from_bytes(low_bytes));
    ba.append(@ByteArrayExTrait::from_bytes(high_bytes));
    ba.into_bytes()
}

pub fn deserialize_u256(value: u256) -> Span<u8> {
    // Bu fonksiyonu tamamla
    let mut ba: core::byte_array::ByteArray = Default::default();

    if (value.high > 0_u128) {
        let low_bytes = deserialize_bytes(value.low.into(), 16);
        let high_bytes = deserialize_bytes_non_zeroes(value.high.into(), 16);
        ba.append(@ByteArrayExTrait::from_bytes(low_bytes));
        ba.append(@ByteArrayExTrait::from_bytes(high_bytes));
    } else {
        let low_bytes = deserialize_bytes_non_zeroes(value.low.into(), 16);
        ba.append(@ByteArrayExTrait::from_bytes(low_bytes));
    }
    ba.into_bytes_without_initial_zeroes()
}

// Deserializes u256s into u8 bytes. It doesnt removes zeroes, it fits the u256s into 32 byte
// always.
pub fn deserialize_u256_span(ref value: Span<u256>) -> Span<u8> {
    let mut ba = Default::default();
    loop {
        match value.pop_front() {
            Option::None => { break; },
            Option::Some(val) => {
                let mut inner_ba: core::byte_array::ByteArray = Default::default();
                // zerolari silmiyoruz cunku calldata icin kullanilacak
                let low_bytes = deserialize_bytes((*val).low.into(), 16);
                let high_bytes = deserialize_bytes((*val).high.into(), 16);
                inner_ba.append(@ByteArrayExTrait::from_bytes(high_bytes));
                inner_ba.append(@ByteArrayExTrait::from_bytes(low_bytes));

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
    use crate::accounts::encoding::{
        Eip1559Transaction, LegacyTransaction, rlp_encode_eip1559, rlp_encode_legacy, deserialize_bytes_non_zeroes, bytes_from_felts,
        deserialize_u256, deserialize_u256_span
    };
    use crate::utils::transaction::eip2930::{AccessListItem};
    use core::num::traits::{Bounded};

    #[test]
    fn rlp_encode_legacy_transaction_empty_calldata() {
        let tx = LegacyTransaction {
            chain_id: 1381192787,
            nonce: 6,
            gas_limit: 21000,
            gas_price: 151515,
            value: 0,
            to: 0xDC1Be555a2B02aEd499141FF9fAF1A13934a5D2d.try_into().unwrap(),
            input: array![].span(),
        };

        let encoded = rlp_encode_legacy(tx);
        assert_eq!(encoded.len(), 39);
        assert_eq!(*encoded.at(0), 0xE6);
        assert_eq!(*encoded.at(1), 0x06);
        assert_eq!(*encoded.at(2), 0x83);
        assert_eq!(*encoded.at(3), 0x02);
        assert_eq!(*encoded.at(4), 0x4F);
    }

    #[test]
    fn rlp_encode_legacy_transaction_with_calldata() {
        let tx = LegacyTransaction {
            chain_id: 1381192787,
            nonce: 3,
            gas_limit: 21000,
            gas_price: 151515,
            value: 0,
            to: 0xDC1Be555a2B02aEd499141FF9fAF1A13934a5D2d.try_into().unwrap(),
            input: array![0xAB, 0xCA, 0xBC].span(),
        };

        let encoded = rlp_encode_legacy(tx);
        assert_eq!(encoded.len(), 42);
        assert_eq!(*encoded.at(0), 0xE9);
        assert_eq!(*encoded.at(1), 0x03);
        assert_eq!(*encoded.at(2), 0x83);
        assert_eq!(*encoded.at(3), 0x02);
        assert_eq!(*encoded.at(4), 0x4F);
        assert_eq!(*encoded.at(39), 0x53);
    }

    #[test]
    fn rlp_encode_eip1559_transaction() {
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
        assert_eq!(*encoded.at(0), 0x02);
        assert_eq!(*encoded.at(1), 0xEC);
        assert_eq!(*encoded.at(2), 0x82);
        assert_eq!(*encoded.at(3), 0x0B);
        assert_eq!(*encoded.at(4), 0x75);
    }

    #[test]
    #[ignore] // Ignoring this. access list will always be empty
    fn rlp_encode_access_list() {
        let access_list_item = AccessListItem {
            ethereum_address: 0x5703ff58bB0CA34F870a8bC18dDd541f29375978.try_into().unwrap(),
            storage_keys: array![0_u256, 1_u256].span()
        };
        let tx = Eip1559Transaction {
            chain_id: 11155111,
            nonce: 87,
            max_priority_fee_per_gas: 1638611,
            max_fee_per_gas: 16357352599,
            gas_limit: 21000,
            to: 0xC7f5D5D3725f36CF36477B84010EB8DdE42D3636.try_into().unwrap(),
            value: 0x0,
            input: array![0xf4, 0xac, 0xc7, 0xb5].span(),
            access_list: array![access_list_item].span(),
        };

        let encoded = rlp_encode_eip1559(tx);
        assert_eq!(encoded.len(), 142);
    }

    #[test]
    fn rlp_encode_transaction_value() {
        // rlp encoded
        // 0x02eb83aa36a73784096cdd46850a1baf4a0e82520894b756b1bc042fa70d85ee84eab646a3b438a285ee0180c0
        let tx = Eip1559Transaction {
            chain_id: 11155111,
            nonce: 55,
            max_priority_fee_per_gas: 158129478,
            max_fee_per_gas: 43414145550,
            gas_limit: 21000,
            to: 0xB756B1BC042Fa70D85Ee84eab646a3b438A285Ee.try_into().unwrap(),
            value: 1,
            input: array![].span(),
            access_list: array![].span()
        };

        let mut encoded = rlp_encode_eip1559(tx);
        assert_eq!(encoded.len(), 45);
        assert_eq!(*encoded.at(0), 0x02);
        assert_eq!(*encoded.at(9), 0x6c);
        assert_eq!(*encoded.at(18), 0x82);
        assert_eq!(*encoded.at(20), 0x08);
        assert_eq!(*encoded.at(29), 0x0d);
        assert_eq!(*encoded.at(44), 0xc0);
    }

    #[test]
    fn test_deserialize_u256() {
        let deserialized = deserialize_u256(1);
        assert_eq!(deserialized.len(), 1);
        assert_eq!(*deserialized.at(0), 0x01);
    }

    #[test]
    fn test_deserialize_u256_span() {
        let mut value = array![u256 { high: 0, low: 1 }].span();

        let deserialized = deserialize_u256_span(ref value);
        assert_eq!(deserialized.len(), 32);
        assert_eq!(*deserialized.at(0), 0x00);
        assert_eq!(*deserialized.at(31), 0x01);
    }

    #[test]
    fn test_deserialize_u256_span_low_max() {
        let mut value = array![u256 { high: 0, low: Bounded::<u128>::MAX }].span();

        let deserialized = deserialize_u256_span(ref value);
        assert_eq!(deserialized.len(), 32);
        assert_eq!(*deserialized.at(0), 0x00);
        assert_eq!(*deserialized.at(16), 0xFF);
        assert_eq!(*deserialized.at(22), 0xFF);
        assert_eq!(*deserialized.at(31), 0xFF);
    }

    #[test]
    fn test_deserialize_u256_span_high_max() {
        let mut value = array![u256 { high: Bounded::<u128>::MAX, low: 0 }].span();

        let deserialized = deserialize_u256_span(ref value);
        assert_eq!(deserialized.len(), 32);
        assert_eq!(*deserialized.at(0), 0xFF);
        assert_eq!(*deserialized.at(8), 0xFF);
        assert_eq!(*deserialized.at(15), 0xFF);
        assert_eq!(*deserialized.at(16), 0x00);
        assert_eq!(*deserialized.at(22), 0x00);
        assert_eq!(*deserialized.at(31), 0x00);
    }

    #[test]
    fn test_deserialize_u256_span_max() {
        let mut value = array![u256 { high: Bounded::<u128>::MAX, low: Bounded::<u128>::MAX }]
            .span();

        let deserialized = deserialize_u256_span(ref value);
        assert_eq!(deserialized.len(), 32);
        assert_eq!(*deserialized.at(0), 0xFF);
        assert_eq!(*deserialized.at(8), 0xFF);
        assert_eq!(*deserialized.at(15), 0xFF);
        assert_eq!(*deserialized.at(16), 0xFF);
        assert_eq!(*deserialized.at(22), 0xFF);
        assert_eq!(*deserialized.at(31), 0xFF);
    }

    #[test]
    fn test_deserialize_u256_span_zero() {
        let mut value = array![u256 { high: 0, low: 0 }].span();

        let deserialized = deserialize_u256_span(ref value);
        assert_eq!(deserialized.len(), 32);
        assert_eq!(*deserialized.at(0), 0x00);
        assert_eq!(*deserialized.at(31), 0x00);
    }

    #[test]
    fn test_deserialize_u256_span_multi_zero() {
        let mut value = array![u256 { high: 0, low: 0 }, u256 { high: 0, low: 0 }].span();

        let deserialized = deserialize_u256_span(ref value);
        assert_eq!(deserialized.len(), 64);
        assert_eq!(*deserialized.at(0), 0x00);
        assert_eq!(*deserialized.at(31), 0x00);
        assert_eq!(*deserialized.at(32), 0x00);
        assert_eq!(*deserialized.at(63), 0x00);
    }

    #[test]
    fn test_deserialize_u256_span_multi_max() {
        let mut value = array![
            u256 { high: Bounded::<u128>::MAX, low: Bounded::<u128>::MAX },
            u256 { high: Bounded::<u128>::MAX, low: Bounded::<u128>::MAX }
        ]
            .span();

        let deserialized = deserialize_u256_span(ref value);
        assert_eq!(deserialized.len(), 64);
        assert_eq!(*deserialized.at(0), 0xFF);
        assert_eq!(*deserialized.at(31), 0xFF);
        assert_eq!(*deserialized.at(32), 0xFF);
        assert_eq!(*deserialized.at(63), 0xFF);
    }

    #[test]
    fn test_byte_array_from_felts() {
        let mut arr = array![0x7837, 0x1234].span();

        let ba = bytes_from_felts(ref arr);

        assert_eq!(*ba.at(0), 0x78);
        assert_eq!(*ba.at(1), 0x37);
        assert_eq!(*ba.at(2), 0x12);
        assert_eq!(*ba.at(3), 0x34);
    }

    #[test]
    fn test_byte_array_from_felts_long() {
        // ASCII of transfer(address,uint256)
        let mut arr = array![0x7472616E7366657228616464726573732C75696E7432353629].span();

        let ba = bytes_from_felts(ref arr);

        assert_eq!(*ba.at(0), 0x74);
        assert_eq!(*ba.at(1), 0x72);
        assert_eq!(*ba.at(2), 0x61);
        assert_eq!(*ba.at(3), 0x6E);
    }


    #[test]
    fn test_byte_array_from_felts_long_two() {
        // ASCII of transferFrom(address,address,uint256)
        let mut arr = array![
            0x7472616E7366657246726F6D28616464726573732C616464726573732C, 0x75696E7432353629
        ]
            .span();

        let ba = bytes_from_felts(ref arr);

        assert_eq!(*ba.at(0), 0x74);
        assert_eq!(*ba.at(1), 0x72);
        assert_eq!(*ba.at(29), 0x75);
        assert_eq!(*ba.at(30), 0x69);
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
