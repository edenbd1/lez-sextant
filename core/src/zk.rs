//! The zkcrypto `bls12_381` backend (RISC Zero's fork in the accelerated
//! guest). Kept for comparison: it is what r0vm-helios and SP1 Helios build
//! on, and it measures about 2.8 times slower than blst on the pairing path.

use crate::bls::{KeyMode, DST};
use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt};

pub fn decode_key(compressed: &[u8; 48], mode: KeyMode, witness: Option<&[u8]>) -> Option<G1Affine> {
    match mode {
        KeyMode::Checked => Option::from(G1Affine::from_compressed(compressed)),
        KeyMode::Unchecked => Option::from(G1Affine::from_compressed_unchecked(compressed)),
        KeyMode::Witness => {
            let raw: &[u8; 96] = witness?.try_into().ok()?;
            let p = Option::<G1Affine>::from(G1Affine::from_uncompressed_unchecked(raw))?;
            let ok = bool::from(p.is_on_curve()) && !bool::from(p.is_identity()) && &p.to_compressed() == compressed;
            ok.then_some(p)
        }
    }
}

/// `plus` summed, minus `minus` summed, as an uncompressed G1 point.
pub fn combine(plus: &[G1Affine], minus: &[G1Affine]) -> [u8; 96] {
    let mut acc = G1Projective::identity();
    for p in plus {
        acc = acc.add_mixed(p);
    }
    for p in minus {
        acc = acc.add_mixed(&-p);
    }
    G1Affine::from(acc).to_uncompressed()
}

pub fn hash_to_g2(msg: &[u8]) -> [u8; 192] {
    let p = <G2Projective as HashToCurve<ExpandMsgXmd<sha2_09::Sha256>>>::hash_to_curve(msg, DST);
    G2Affine::from(p).to_uncompressed()
}

pub fn decode_signature(sig: &[u8; 96]) -> Option<[u8; 192]> {
    let s = Option::<G2Affine>::from(G2Affine::from_compressed(sig))?;
    (!bool::from(s.is_identity())).then(|| s.to_uncompressed())
}

/// `e(pk, hm) == e(g1, sig)`; points already validated, given uncompressed.
pub fn pairing_check(pk: &[u8; 96], hm: &[u8; 192], sig: &[u8; 192]) -> bool {
    let pk = Option::<G1Affine>::from(G1Affine::from_uncompressed_unchecked(pk)).expect("a validated point");
    let hm = Option::<G2Affine>::from(G2Affine::from_uncompressed_unchecked(hm)).expect("a validated point");
    let sig = Option::<G2Affine>::from(G2Affine::from_uncompressed_unchecked(sig)).expect("a validated point");
    let neg_g1 = -G1Affine::generator();
    let a = G2Prepared::from(hm);
    let b = G2Prepared::from(sig);
    multi_miller_loop(&[(&pk, &a), (&neg_g1, &b)]).final_exponentiation() == Gt::identity()
}

/// The pairing check by stage, for the benchmark: `(prepare, loop, final exp)`.
pub fn pairing_stages(pk: &[u8; 96], hm: &[u8; 192], sig: &[u8; 192], mark: &mut dyn FnMut(&'static str)) -> bool {
    let pk = Option::<G1Affine>::from(G1Affine::from_uncompressed_unchecked(pk)).expect("a validated point");
    let hm = Option::<G2Affine>::from(G2Affine::from_uncompressed_unchecked(hm)).expect("a validated point");
    let sig = Option::<G2Affine>::from(G2Affine::from_uncompressed_unchecked(sig)).expect("a validated point");
    mark("decode_uncompressed");
    let neg_g1 = -G1Affine::generator();
    let a = G2Prepared::from(hm);
    let b = G2Prepared::from(sig);
    mark("g2_prepare_x2");
    let f = multi_miller_loop(&[(&pk, &a), (&neg_g1, &b)]);
    mark("miller_loop_x2");
    let ok = f.final_exponentiation() == Gt::identity();
    mark("final_exponentiation");
    ok
}
