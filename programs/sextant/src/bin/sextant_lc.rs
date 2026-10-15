// sextant_lc (RFP-021 prototype) for LEZ v0.3: the whole program is
// `sextant_program::{plan, apply}`; this binary hands them to the v0.3 entry point.

fn main() {
    lee_core::program::run_program::<_, _, [u8], Vec<u8>>(sextant_program::plan, sextant_program::apply)
}
