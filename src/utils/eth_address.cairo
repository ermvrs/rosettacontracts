use core::starknet::EthAddress;
use crate::utils::math::Bitshift;
use crate::utils::traits::{EthAddressIntoU256};

#[generate_trait]
pub impl EthAddressExImpl of EthAddressExTrait {
    const BYTES_USED: u8 = 20;
    /// Converts an EthAddress to an array of bytes.
    ///
    /// # Returns
    ///
    /// * `Array<u8>` - A 20-byte array representation of the EthAddress.
    fn to_bytes(self: EthAddress) -> Array<u8> {
        let value: u256 = self.into();
        let mut bytes: Array<u8> = Default::default();
        for i in 0
            ..Self::BYTES_USED {
                let val = value.shr(8_u32 * (Self::BYTES_USED.into() - i.into() - 1));
                bytes.append((val & 0xFF).try_into().unwrap());
            };

        bytes
    }

    /// Converts a 20-byte array into an EthAddress.
    ///
    /// # Arguments
    ///
    /// * `input` - A `Span<u8>` of length 20 representing the bytes of an Ethereum address.
    ///
    /// # Returns
    ///
    /// * `Option<EthAddress>` - `Some(EthAddress)` if the conversion succeeds, `None` if the input
    /// length is not 20.
    fn from_bytes(input: Span<u8>) -> Option<EthAddress> {
        let len = input.len();
        if len != 20 {
            return Option::None;
        }
        let offset: u32 = len - 1;
        let mut result: u256 = 0;
        for i in 0
            ..len {
                let byte: u256 = (*input.at(i)).into();
                result += byte.shl((8 * (offset - i)));
            };
        result.try_into()
    }
}
