#[derive(Copy, Drop, Serde)]
pub struct EthereumFunction {
    sn_selector: felt252,
    decoding_directives: Span<DecodingDirective>
}

#[derive(Copy, Drop, Serde, PartialEq)]
pub enum DecodingDirective {
    Uint256,
    Address,
    // TBD
}
