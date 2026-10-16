// erc20_receiver (RFP-021 prototype) for LEZ v0.3: the whole program is
// `erc20_receiver::{plan, apply}`; this binary hands them to the v0.3 entry point.

fn main() {
    lee_core::program::run_program::<_, _, [u8], Vec<u8>>(erc20_receiver::plan, erc20_receiver::apply)
}
