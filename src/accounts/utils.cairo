use starknet::secp256_trait::{Signature};
use starknet::secp256_trait;
use rosettacontracts::accounts::base::{EthPublicKey};
use starknet::{EthAddress};
use crate::utils::transaction::eip2930::{AccessListItem};
use starknet::eth_signature::{verify_eth_signature, public_key_point_to_eth_address};

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
    input: Span<felt252>,
    access_list: Span<AccessListItem>
}

#[derive(Copy, Drop, Serde)]
pub struct RosettanetSignature {
    pub v: u32, // 27 or 28
    pub r: u256,
    pub s: u256,
    pub y_parity: u32 // 0 or 1
}

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

pub fn verify_transaction(signature: RosettanetSignature) -> bool {
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
}