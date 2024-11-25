use starknet::secp256_trait::{Signature};
use starknet::secp256_trait;
use rosettacontracts::accounts::base::{EthPublicKey};
use starknet::{EthAddress};
use crate::utils::transaction::eip2930::{AccessListItem};
use crate::utils::rlp::{RLPTrait, RLPItem, RLPHelpersTrait};
use crate::utils::traits::SpanDefault;
use crate::errors::{EthTransactionError, RLPError, RLPErrorTrait};
use crate::utils::bytes::{U8SpanExTrait};
use starknet::eth_signature::{verify_eth_signature, public_key_point_to_eth_address};
use core::num::traits::SaturatingSub;

#[derive(Copy, Drop, Serde)]
pub struct EthSignature {
    pub r: u256,
    pub s: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct RosettanetTransaction {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u128,
    max_fee_per_gas: u128,
    gas_limit: u64,
    to: EthAddress,
    value: u256,
    input: Span<u8>,
    access_list: Span<AccessListItem>,
    hash: u256
}

#[derive(Copy, Drop, Serde)]
pub struct RosettanetSignature {
    pub v: u32, // 27 or 28
    pub r: u256,
    pub s: u256,
    pub y_parity: u32 // 0 or 1
}

// Merges u256s coming from calldata according to directives
pub fn merge_u256s(calldata: Span<felt252>, directives: Span<bool>) -> Span<u256> {
    assert(calldata.len() == directives.len(), 'R-AU-1 Sanity check fails');
    let mut merged_array = ArrayTrait::<u256>::new();
    let mut index = 0;

    while index < calldata.len() {
        let current_directive = *directives.at(index);
        if(current_directive) {
            let element = u256 {
                low: (*calldata.at(index)).try_into().unwrap(), // We can assume it always fits u128 limit since u256s already splitted low highs
                high: (*calldata.at(index + 1)).try_into().unwrap()
            };
            merged_array.append(element);
            index +=1;
        } else {
            merged_array.append((*calldata.at(index)).into());
        }
        index +=1;
    };

    merged_array.span()
}

#[inline(always)]
pub fn compute_hash(encoded_tx_data: Span<u8>) -> u256 {
    encoded_tx_data.compute_keccak256_hash()
}

pub fn decode_encoded_eip1559_transaction(ref encoded_tx: Span<u8>) -> Result<RosettanetTransaction, EthTransactionError> {
    let original_data = encoded_tx;
    let rlp_decoded_data = RLPTrait::decode(encoded_tx).map_err()?;
    //if (rlp_decoded_data.len() != 1) {
        // todo Error
    //    EthTransactionError::RLPError(RLPError::Custom('not encoded as list'))
    //}

    let mut rlp_decoded_data = match *rlp_decoded_data.at(0) {
        RLPItem::String => {
            return Result::Err(
                EthTransactionError::RLPError(RLPError::Custom('not encoded as list'))
            );
        },
        RLPItem::List(v) => { v }
    };

    let boxed_fields = rlp_decoded_data
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
    let to = to_encoded.try_parse_address_from_string().map_err()?.unwrap();
    let value = value_encoded.parse_u256_from_string().map_err()?;
    let input = input_encoded.parse_bytes_from_string().map_err()?;
    let access_list = access_list_encoded.parse_access_list().map_err()?;

    let hash = compute_hash(original_data);

    let tx = RosettanetTransaction {
        chain_id,
        nonce,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit,
        to,
        value,
        input,
        access_list,
        hash
    };

    Result::Ok(tx)
}

pub fn verify_transaction(tx: RosettanetTransaction, signature: RosettanetSignature) -> bool {
    true
}

pub fn pubkey_to_eth_address(public_key: EthPublicKey) -> EthAddress {
    public_key_point_to_eth_address(public_key)
}

pub fn is_valid_eth_signature(
    msg_hash: felt252, public_key: EthPublicKey, signature: Span<felt252>
) -> bool {
    let mut signature = signature;
    let signature: EthSignature = Serde::deserialize(ref signature)
        .expect('Signature: Invalid format.');

    secp256_trait::is_valid_signature(msg_hash.into(), signature.r, signature.s, public_key)
}

pub fn is_valid_eth_signature_with_eth_address(
    msg_hash:u256, signature: Signature, eth_address: EthAddress
) {
    verify_eth_signature(msg_hash, signature, eth_address)
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts for Cairo v0.17.0 (account/utils/secp256k1.cairo)

use core::fmt::{Formatter, Error};
use starknet::SyscallResultTrait;
use starknet::secp256_trait::{Secp256Trait, Secp256PointTrait};
use starknet::secp256k1::Secp256k1Point;
use starknet::storage_access::StorePacking;

/// Packs a Secp256k1Point into a (felt252, felt252).
///
/// The packing is done as follows:
/// - First felt contains x.low (x being the x-coordinate of the point).
/// - Second felt contains x.high and the parity bit, at the least significant bits (2 * x.high +
/// parity).
pub impl Secp256k1PointStorePacking of StorePacking<Secp256k1Point, (felt252, felt252)> {
    fn pack(value: Secp256k1Point) -> (felt252, felt252) {
        let (x, y) = value.get_coordinates().unwrap_syscall();

        let parity = y % 2;
        let xhigh_and_parity = 2 * x.high.into() + parity.try_into().unwrap();

        (x.low.into(), xhigh_and_parity)
    }

    fn unpack(value: (felt252, felt252)) -> Secp256k1Point {
        let (xlow, xhigh_and_parity) = value;
        let xhigh_and_parity: u256 = xhigh_and_parity.into();

        let x = u256 {
            low: xlow.try_into().unwrap(), high: (xhigh_and_parity / 2).try_into().unwrap(),
        };
        let parity = xhigh_and_parity % 2 == 1;

        // Expects parity odd to be true
        Secp256Trait::secp256_ec_get_point_from_x_syscall(x, parity)
            .unwrap_syscall()
            .expect('Secp256k1Point: Invalid point.')
    }
}

pub impl Secp256k1PointPartialEq of PartialEq<Secp256k1Point> {
    #[inline(always)]
    fn eq(lhs: @Secp256k1Point, rhs: @Secp256k1Point) -> bool {
        (*lhs).get_coordinates().unwrap_syscall() == (*rhs).get_coordinates().unwrap_syscall()
    }
    #[inline(always)]
    fn ne(lhs: @Secp256k1Point, rhs: @Secp256k1Point) -> bool {
        !(lhs == rhs)
    }
}

pub impl DebugSecp256k1Point of core::fmt::Debug<Secp256k1Point> {
    fn fmt(self: @Secp256k1Point, ref f: Formatter) -> Result<(), Error> {
        let (x, y) = (*self).get_coordinates().unwrap_syscall();
        write!(f, "({x:?},{y:?})")
    }
}

#[cfg(test)]
mod tests {
    use crate::accounts::utils::{merge_u256s};

    #[test]
    fn test_merge_one() {
        let data = array![0xFF, 0xAB].span();
        let directive = array![true, false].span();

        let merged = merge_u256s(data, directive);

        assert_eq!(*merged.at(0), u256 {low: 0xFF, high: 0xAB});
    }

    #[test]
    fn test_merge_two() {
        let data = array![0xFF, 0xAB, 0x123123, 0x0].span();
        let directive = array![true, false, true, false].span();

        let merged = merge_u256s(data, directive);

        assert_eq!(*merged.at(0), u256 {low: 0xFF, high: 0xAB});
        assert_eq!(*merged.at(1), u256 {low: 0x123123, high: 0x0});
    }

    #[test]
    #[should_panic(expected: 'R-AU-1 Sanity check fails')]
    fn test_merge_wrong_sanity() {
        let data = array![0xFF, 0xAB, 0x123123, 0x0].span();
        let directive = array![true, false, true, false, true].span();

        let merged = merge_u256s(data, directive);

        assert_eq!(*merged.at(0), u256 {low: 0xFF, high: 0xAB});
        assert_eq!(*merged.at(1), u256 {low: 0x123123, high: 0x0});
    }

    // Decode tests

    use crate::accounts::utils::{decode_encoded_eip1559_transaction, RosettanetTransaction};
    use crate::utils::test_data::{eip_1559_encoded_tx};

    #[test]
    fn test_decode_eip1559() {
        let mut data = eip_1559_encoded_tx();

        let decoded_tx: RosettanetTransaction = decode_encoded_eip1559_transaction(ref data).unwrap();

        assert_eq!(decoded_tx.nonce, 0);
        assert_eq!(decoded_tx.chain_id, 0x4b4b5254);
        assert_eq!(decoded_tx.value, 0x016345785d8a0000);
    }
}