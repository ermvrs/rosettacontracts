
use core::array::ArrayTrait;
use core::array::SpanTrait;
use core::option::OptionTrait;
use core::panic_with_felt252;
use core::starknet::EthAddress;
use crate::errors::{RLPError};
use crate::utils::transaction::eip2930::AccessListItem;
use crate::utils::array::ArrayExtension;
use crate::utils::bytes::{ToBytes, FromBytes};
use crate::utils::eth_address::EthAddressExTrait;


// Possible RLP types
#[derive(Drop, PartialEq, Debug)]
pub enum RLPType {
    String,
    List
}

#[derive(Drop, Copy, PartialEq, Debug)]
pub enum RLPItem {
    String: Span<u8>,
    List: Span<RLPItem>
}

#[generate_trait]
pub impl RLPImpl of RLPTrait {
    /// Returns RLPType from the leading byte with
    /// its offset in the array as well as its size.
    ///
    /// # Arguments
    /// * `input` - Span of bytes to decode
    ///
    /// # Returns
    /// * `Result<(RLPType, u32, u32), RLPError>` - A tuple containing the RLPType,
    ///   the offset, and the size of the RLPItem to decode
    ///
    /// # Errors
    /// * `RLPError::EmptyInput` - if the input is empty
    /// * `RLPError::InputTooShort` - if the input is too short for a given type
    /// * `RLPError::InvalidInput` - if the input is invalid
    fn decode_type(input: Span<u8>) -> Result<(RLPType, u32, u32), RLPError> {
        let input_len = input.len();
        if input_len == 0 {
            return Result::Err(RLPError::EmptyInput);
        }

        let prefix = *input[0];

        if prefix < 0x80 { // Char
            Result::Ok((RLPType::String, 0, 1))
        } else if prefix < 0xb8 { // Short String
            Result::Ok((RLPType::String, 1, prefix.into() - 0x80))
        } else if prefix < 0xc0 { // Long String
            let len_bytes_count: u32 = (prefix - 0xb7).into();
            if input_len <= len_bytes_count {
                return Result::Err(RLPError::InputTooShort);
            }
            let string_len_bytes = input.slice(1, len_bytes_count);
            let string_len: u32 = string_len_bytes
                .from_be_bytes_partial()
                .expect('rlp_decode_type_string_len');
            if input_len <= len_bytes_count + string_len {
                return Result::Err(RLPError::InputTooShort);
            }

            Result::Ok((RLPType::String, 1 + len_bytes_count, string_len))
        } else if prefix < 0xf8 { // Short List
            let list_len: u32 = prefix.into() - 0xc0;
            if input_len <= list_len {
                return Result::Err(RLPError::InputTooShort);
            }
            Result::Ok((RLPType::List, 1, list_len))
        } else if prefix <= 0xff { // Long List
            let len_bytes_count = prefix.into() - 0xf7;
            if input.len() <= len_bytes_count {
                return Result::Err(RLPError::InputTooShort);
            }
            let list_len_bytes = input.slice(1, len_bytes_count);
            let list_len: u32 = list_len_bytes
                .from_be_bytes_partial()
                .expect('rlp_decode_type_list_len');
            if input_len <= len_bytes_count + list_len {
                return Result::Err(RLPError::InputTooShort);
            }
            Result::Ok((RLPType::List, 1 + len_bytes_count, list_len))
        } else {
            Result::Err(RLPError::InvalidInput)
        }
    }

    /// RLP encodes a sequence of RLPItems
    ///
    /// # Arguments
    /// * `input` - Span of RLPItems to encode
    ///
    /// # Returns
    /// * `Span<u8>` - RLP encoded byte array
    ///
    /// # Panics
    /// * If encoding a long sequence (should not happen in current implementation)
    fn encode_sequence(mut input: Span<RLPItem>) -> Span<u8> {
        let mut joined_encodings: Array<u8> = Default::default();
        for item in input {
            match item {
                RLPItem::String(string) => {
                    joined_encodings.append_span(Self::encode_string(*string));
                },
                RLPItem::List(_) => { panic_with_felt252('List encoding unimplemented') }
            }
        };
        let len_joined_encodings = joined_encodings.len();
        if len_joined_encodings < 0x38 {
            let mut result: Array<u8> = array![0xC0 + len_joined_encodings.try_into().unwrap()];
            result.append_span(joined_encodings.span());
            return result.span();
        } else {
            // Actual implementation of long list encoding is commented out
            // as we should never reach this point in the current implementation
            // let bytes_count_len_joined_encodings = len_joined_encodings.bytes_used();
            // let len_joined_encodings: Span<u8> = len_joined_encodings.to_bytes();
            // let mut result = array![0xF7 + bytes_count_len_joined_encodings];
            // result.append_span(len_joined_encodings);
            // result.append_span(joined_encodings.span());
            // return result.span();
            return panic_with_felt252('Shouldnt encode long sequence');
        }
    }

    /// RLP encodes a Span<u8>, which is the underlying type used to represent
    /// string data in Cairo.
    ///
    /// # Arguments
    /// * `input` - Span<u8> to encode
    ///
    /// # Returns
    /// * `Span<u8>` - RLP encoded byte array
    fn encode_string(input: Span<u8>) -> Span<u8> {
        let len = input.len();
        if len == 0 {
            return [0x80].span();
        } else if len == 1 && *input[0] < 0x80 {
            return input;
        } else if len < 56 {
            let mut encoding: Array<u8> = Default::default();
            encoding.append(0x80 + len.try_into().unwrap());
            encoding.append_span(input);
            return encoding.span();
        } else {
            let mut encoding: Array<u8> = Default::default();
            let len_as_bytes = len.to_be_bytes();
            let len_bytes_count = len_as_bytes.len();
            let prefix = 0xb7 + len_bytes_count.try_into().unwrap();
            encoding.append(prefix);
            encoding.append_span(len_as_bytes);
            encoding.append_span(input);
            return encoding.span();
        }
    }

    /// RLP decodes a rlp encoded byte array
    /// as described in https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
    ///
    /// # Arguments
    /// * `input` - Span of bytes to decode
    ///
    /// # Returns
    /// * `Result<Span<RLPItem>, RLPError>` - Span of RLPItems
    ///
    /// # Errors
    /// * `RLPError::InputTooShort` - if the input is too short for a given type
    fn decode(input: Span<u8>) -> Result<Span<RLPItem>, RLPError> {
        let mut output: Array<RLPItem> = Default::default();
        let input_len = input.len();

        let (rlp_type, offset, len) = Self::decode_type(input)?;

        if input_len < offset + len {
            return Result::Err(RLPError::InputTooShort);
        }

        match rlp_type {
            RLPType::String => {
                if (len == 0) {
                    output.append(RLPItem::String([].span()));
                } else {
                    output.append(RLPItem::String(input.slice(offset, len)));
                }
            },
            RLPType::List => {
                if len == 0 {
                    output.append(RLPItem::List([].span()));
                } else {
                    let res = Self::decode(input.slice(offset, len))?;
                    output.append(RLPItem::List(res));
                }
            }
        };

        let total_item_len = len + offset;
        if total_item_len < input_len {
            output
                .append_span(
                    Self::decode(input.slice(total_item_len, input_len - total_item_len))?
                );
        }

        Result::Ok(output.span())
    }
}

#[generate_trait]
pub impl RLPHelpersImpl of RLPHelpersTrait {
    /// Parses a u64 from an RLPItem::String
    ///
    /// # Returns
    /// * `Result<u64, RLPError>` - The parsed u64 value
    ///
    /// # Errors
    /// * `RLPError::NotAString` - if the RLPItem is not a String
    fn parse_u64_from_string(self: RLPItem) -> Result<u64, RLPError> {
        match self {
            RLPItem::String(bytes) => {
                // Empty strings means 0
                if bytes.len() == 0 {
                    return Result::Ok(0);
                }
                let value = bytes.from_be_bytes_partial().expect('parse_u64_from_string');
                Result::Ok(value)
            },
            RLPItem::List(_) => { Result::Err(RLPError::NotAString) }
        }
    }

    /// Parses a u128 from an RLPItem::String
    ///
    /// # Returns
    /// * `Result<u128, RLPError>` - The parsed u128 value
    ///
    /// # Errors
    /// * `RLPError::NotAString` - if the RLPItem is not a String
    fn parse_u128_from_string(self: RLPItem) -> Result<u128, RLPError> {
        match self {
            RLPItem::String(bytes) => {
                // Empty strings means 0
                if bytes.len() == 0 {
                    return Result::Ok(0);
                }
                let value = bytes.from_be_bytes_partial().expect('parse_u128_from_string');
                Result::Ok(value)
            },
            RLPItem::List(_) => { Result::Err(RLPError::NotAString) }
        }
    }

    /// Tries to parse an EthAddress from an RLPItem::String
    ///
    /// # Returns
    /// * `Result<Option<EthAddress>, RLPError>` - The parsed EthAddress, if present
    ///
    /// # Errors
    /// * `RLPError::NotAString` - if the RLPItem is not a String
    /// * `RLPError::FailedParsingAddress` - if the address parsing fails
    fn try_parse_address_from_string(self: RLPItem) -> Result<Option<EthAddress>, RLPError> {
        match self {
            RLPItem::String(bytes) => {
                if bytes.len() == 0 {
                    return Result::Ok(Option::None);
                }
                if bytes.len() == 20 {
                    let maybe_value = EthAddressExTrait::from_bytes(bytes);
                    return Result::Ok(maybe_value);
                }
                return Result::Err(RLPError::FailedParsingAddress);
            },
            RLPItem::List(_) => { Result::Err(RLPError::NotAString) }
        }
    }

    /// Parses a u256 from an RLPItem::String
    ///
    /// # Returns
    /// * `Result<u256, RLPError>` - The parsed u256 value
    ///
    /// # Errors
    /// * `RLPError::NotAString` - if the RLPItem is not a String
    fn parse_u256_from_string(self: RLPItem) -> Result<u256, RLPError> {
        match self {
            RLPItem::String(bytes) => {
                // Empty strings means 0
                if bytes.len() == 0 {
                    return Result::Ok(0);
                }
                let value = bytes.from_be_bytes_partial().expect('parse_u256_from_string');
                Result::Ok(value)
            },
            RLPItem::List(_) => { Result::Err(RLPError::NotAString) }
        }
    }

    /// Parses bytes from an RLPItem::String
    ///
    /// # Returns
    /// * `Result<Span<u8>, RLPError>` - The parsed bytes
    ///
    /// # Errors
    /// * `RLPError::NotAString` - if the RLPItem is not a String
    fn parse_bytes_from_string(self: RLPItem) -> Result<Span<u8>, RLPError> {
        match self {
            RLPItem::String(bytes) => { Result::Ok(bytes) },
            RLPItem::List(_) => { Result::Err(RLPError::NotAString) }
        }
    }

    /// Parses storage keys from an RLPItem
    ///
    /// # Returns
    /// * `Result<Span<u256>, RLPError>` - The parsed storage keys
    ///
    /// # Errors
    /// * `RLPError::NotAList` - if the RLPItem is not a List
    /// * `RLPError::FailedParsingAddress` - if parsing a storage key fails
    fn parse_storage_keys_from_rlp_item(self: RLPItem) -> Result<Span<u256>, RLPError> {
        match self {
            RLPItem::String(_) => { return Result::Err(RLPError::NotAList); },
            RLPItem::List(mut keys) => {
                let mut storage_keys: Array<u256> = array![];
                let storage_keys: Result<Span<u256>, RLPError> = loop {
                    match keys.pop_front() {
                        Option::Some(rlp_item) => {
                            let storage_key = match ((*rlp_item).parse_u256_from_string()) {
                                Result::Ok(storage_key) => { storage_key },
                                Result::Err(err) => { break Result::Err(err); }
                            };

                            storage_keys.append(storage_key);
                        },
                        Option::None => { break Result::Ok(storage_keys.span()); }
                    }
                };

                storage_keys
            }
        }
    }

    /// Parses an access list from an RLPItem
    ///
    /// # Returns
    /// * `Result<Span<AccessListItem>, RLPError>` - The parsed access list
    ///
    /// # Errors
    /// * `RLPError::NotAList` - if the RLPItem is not a List
    /// * `RLPError::InputTooShort` - if the input is too short
    /// * `RLPError::FailedParsingAccessList` - if parsing the access list fails
    fn parse_access_list(self: RLPItem) -> Result<Span<AccessListItem>, RLPError> {
        let mut list_of_accessed_tuples: Span<RLPItem> = match self {
            RLPItem::String(_) => { return Result::Err(RLPError::NotAList); },
            RLPItem::List(list) => list
        };

        let mut parsed_access_list = array![];

        // Iterate over the List of [Tuples (RLPString, RLPList)] representing all access list
        // entries
        let result = loop {
            // Get the front Tuple (RLPString, RLPList)
            let mut inner_tuple = match list_of_accessed_tuples.pop_front() {
                Option::None => { break Result::Ok(parsed_access_list.span()); },
                Option::Some(inner_tuple) => match inner_tuple {
                    RLPItem::String(_) => { break Result::Err(RLPError::NotAList); },
                    RLPItem::List(accessed_tuples) => *accessed_tuples
                }
            };

            match inner_tuple.multi_pop_front::<2>() {
                Option::None => { break Result::Err(RLPError::InputTooShort); },
                Option::Some(inner_tuple) => {
                    let [rlp_address, rlp_keys] = (*inner_tuple).unbox();
                    let ethereum_address = match rlp_address.try_parse_address_from_string() {
                        Result::Ok(maybe_eth_address) => {
                            match (maybe_eth_address) {
                                Option::Some(eth_address) => { eth_address },
                                Option::None => {
                                    break Result::Err(RLPError::FailedParsingAccessList);
                                }
                            }
                        },
                        Result::Err(err) => { break Result::Err(err); }
                    };

                    let storage_keys: Span<u256> =
                        match rlp_keys.parse_storage_keys_from_rlp_item() {
                        Result::Ok(storage_keys) => storage_keys,
                        Result::Err(err) => { break Result::Err(err); }
                    };
                    parsed_access_list.append(AccessListItem { ethereum_address, storage_keys });
                }
            }
        };
        result
    }
}
