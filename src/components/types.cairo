#[derive(Copy, Drop, Serde)]
pub struct EthereumFunction {
    sn_selector: felt252,
    decoding_directives: Span<u8>
}
