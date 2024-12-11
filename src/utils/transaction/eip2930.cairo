use core::starknet::EthAddress;
use crate::utils::transaction::common::TxKind;
use alexandria_encoding::rlp::{RLPItem};
use crate::utils::traits::SpanDefault;
use crate::accounts::encoding::{deserialize_bytes, deserialize_u256_with_zeroes};


#[derive(Copy, Drop, Serde, PartialEq, Debug)]
pub struct AccessListItem {
    pub ethereum_address: EthAddress,
    pub storage_keys: Span<u256>
}

#[generate_trait]
pub impl AccessListItemImpl of AccessListItemTrait {
    fn to_storage_keys(self: @AccessListItem) -> Span<(EthAddress, u256)> {
        let AccessListItem { ethereum_address, mut storage_keys } = *self;

        let mut storage_keys_arr = array![];
        for storage_key in storage_keys {
            storage_keys_arr.append((ethereum_address, *storage_key));
        };

        storage_keys_arr.span()
    }

    fn to_rlp_items(self: @AccessListItem) -> RLPItem {
        let AccessListItem { ethereum_address, mut storage_keys } = *self;

        let mut storage_keys_arr = array![];
        for storage_key in storage_keys {
            storage_keys_arr.append(RLPItem::String(deserialize_u256_with_zeroes(*storage_key))); 
        };

        let addr = RLPItem::String(deserialize_bytes(ethereum_address.into(), 20));
        let keys = RLPItem::List(storage_keys_arr.span());

        RLPItem::List(array![addr, keys].span())
    }
}


/// Transaction with an [`AccessList`] ([EIP-2930](https://eips.ethereum.org/EIPS/eip-2930)).
#[derive(Copy, Drop, Debug, Default, PartialEq, Serde)]
pub struct TxEip2930 {
    /// Added as EIP-pub 155: Simple replay attack protection
    pub chain_id: u64,
    /// A scalar value equal to the number of transactions sent by the sender; formally Tn.
    pub nonce: u64,
    /// A scalar value equal to the number of
    /// Wei to be paid per unit of gas for all computation
    /// costs incurred as a result of the execution of this transaction; formally Tp.
    ///
    /// As ethereum circulation is around 120mil eth as of 2022 that is around
    /// 120000000000000000000000000 wei we are safe to use u128 as its max number is:
    /// 340282366920938463463374607431768211455
    pub gas_price: u128,
    /// A scalar value equal to the maximum
    /// amount of gas that should be used in executing
    /// this transaction. This is paid up-front, before any
    /// computation is done and may not be increased
    /// later; formally Tg.
    pub gas_limit: u64,
    /// The 160-bit address of the message call’s recipient or, for a contract creation
    /// transaction, ∅, used here to denote the only member of B0 ; formally Tt.
    pub to: TxKind,
    /// A scalar value equal to the number of Wei to
    /// be transferred to the message call’s recipient or,
    /// in the case of contract creation, as an endowment
    /// to the newly created account;
    pub value: u256,
    /// The accessList specifies a list of addresses and storage keys;
    /// these addresses and storage keys are added into the `accessed_addresses`
    /// and `accessed_storage_keys` global sets (introduced in EIP-2929).
    /// A gas cost is charged, though at a discount relative to the cost of
    /// accessing outside the list.
    pub access_list: Span<AccessListItem>,
    /// Input has two uses depending if transaction is Create or Call (if `to` field is None or
    /// Some). pub init: An unlimited size byte array specifying the
    /// EVM-code for the account initialisation procedure CREATE,
    /// data: An unlimited size byte array specifying the
    /// input data of the message call;
    pub input: Span<u8>,
}
