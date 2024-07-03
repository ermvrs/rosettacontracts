/// Returns starknet calldata span of felt252s 
/// This function do not checks function selector
/// # Params
/// `offsets` - Calldata read offsets, parse done according to these values
/// `calldata` - Actual EVM calldata, each element presents one slot
/// # Returns
/// `Span<felt252>` - Parsed and converted calldata which is going to be passed to call_contract_syscall.
pub fn parse_calldata(offsets: Span<u128>, calldata: Span<u256>) -> Span<felt252> {

}


/// Finds correct selector with trial and error method
/// It tries to re-calculate ethereum function signature by trying
/// all functions from the input.
/// # Params
/// `functions` - Function names with data types of ethereum span (balanceOf(address), transfer_from(address,address,uint256))
/// `signature` - Actual ethereum function signature from calldata.
pub fn find_selector(functions: Span<ByteArray>, signature: u16) -> felt252 {

}