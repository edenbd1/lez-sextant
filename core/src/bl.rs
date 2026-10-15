//! The blst backend (supranational/blst; RISC Zero's accelerated fork in the
//! guest). This is the program's path: it is the only one of the two whose
//! pairing check splits into transaction-sized steps (a Miller-loop step and
//! a final-exponentiation step, each well under the 10M budget).

use crate::bls::{KeyMode, DST};
use blst::*;

pub type Fp12Bytes = [u8; 576];

fn p1_from_uncompressed(b: &[u8; 96]) -> Option<blst_p1_affine> {
    let mut p = blst_p1_affine::default();
    // Checks the encoding and that the point is on the curve.
    (unsafe { blst_p1_deserialize(&mut p, b.as_ptr()) } == BLST_ERROR::BLST_SUCCESS).then_some(p)
}

fn p2_from_uncompressed(b: &[u8; 192]) -> Option<blst_p2_affine> {
    let mut p = blst_p2_affine::default();
    (unsafe { blst_p2_deserialize(&mut p, b.as_ptr()) } == BLST_ERROR::BLST_SUCCESS).then_some(p)
}

fn p1_bytes(p: &blst_p1_affine) -> [u8; 96] {
    let mut out = [0u8; 96];
    unsafe { blst_p1_affine_serialize(out.as_mut_ptr(), p) };
    out
}

fn p2_bytes(p: &blst_p2_affine) -> [u8; 192] {
    let mut out = [0u8; 192];
    unsafe { blst_p2_affine_serialize(out.as_mut_ptr(), p) };
    out
}

pub fn decode_key(compressed: &[u8; 48], mode: KeyMode, witness: Option<&[u8]>) -> Option<blst_p1_affine> {
    unsafe {
        match mode {
            KeyMode::Checked | KeyMode::Unchecked => {
                let mut p = blst_p1_affine::default();
                if blst_p1_uncompress(&mut p, compressed.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
                    return None;
                }
                (mode == KeyMode::Unchecked || blst_p1_affine_in_g1(&p)).then_some(p)
            }
            KeyMode::Witness => {
                let p = p1_from_uncompressed(witness?.try_into().ok()?)?;
                let mut c = [0u8; 48];
                blst_p1_affine_compress(c.as_mut_ptr(), &p);
                (!blst_p1_affine_is_inf(&p) && &c == compressed).then_some(p)
            }
        }
    }
}

/// `plus` summed, minus `minus` summed, as an uncompressed G1 point.
pub fn combine(plus: &[blst_p1_affine], minus: &[blst_p1_affine]) -> [u8; 96] {
    unsafe {
        let mut acc = blst_p1::default(); // the point at infinity
        for p in plus {
            let a = acc;
            blst_p1_add_or_double_affine(&mut acc, &a, p);
        }
        if !minus.is_empty() {
            let mut neg = blst_p1::default();
            for p in minus {
                let a = neg;
                blst_p1_add_or_double_affine(&mut neg, &a, p);
            }
            blst_p1_cneg(&mut neg, true);
            let a = acc;
            blst_p1_add_or_double(&mut acc, &a, &neg);
        }
        let mut out = blst_p1_affine::default();
        blst_p1_to_affine(&mut out, &acc);
        p1_bytes(&out)
    }
}

pub fn hash_to_g2(msg: &[u8]) -> [u8; 192] {
    unsafe {
        let mut p = blst_p2::default();
        blst_hash_to_g2(&mut p, msg.as_ptr(), msg.len(), DST.as_ptr(), DST.len(), core::ptr::null(), 0);
        let mut a = blst_p2_affine::default();
        blst_p2_to_affine(&mut a, &p);
        p2_bytes(&a)
    }
}

/// Decompression with the subgroup check (`signature_to_point` + `KeyValidate`).
pub fn decode_signature(sig: &[u8; 96]) -> Option<[u8; 192]> {
    unsafe {
        let mut s = blst_p2_affine::default();
        if blst_p2_uncompress(&mut s, sig.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
            return None;
        }
        (blst_p2_affine_in_g2(&s) && !blst_p2_affine_is_inf(&s)).then(|| p2_bytes(&s))
    }
}

fn fp12_bytes(f: &blst_fp12) -> Fp12Bytes {
    let mut out = [0u8; 576];
    let mut i = 0;
    for fp6 in &f.fp6 {
        for fp2 in &fp6.fp2 {
            for fp in &fp2.fp {
                unsafe { blst_bendian_from_fp(out[i..i + 48].as_mut_ptr(), fp) };
                i += 48;
            }
        }
    }
    out
}

fn fp12_from(b: &Fp12Bytes) -> blst_fp12 {
    let mut f = blst_fp12::default();
    let mut i = 0;
    for fp6 in &mut f.fp6 {
        for fp2 in &mut fp6.fp2 {
            for fp in &mut fp2.fp {
                unsafe { blst_fp_from_bendian(fp, b[i..i + 48].as_ptr()) };
                i += 48;
            }
        }
    }
    f
}

/// Step one of the pairing check: `ml(hm, pk) · conj(ml(sig, g1))`, the value
/// whose final exponentiation is `e(pk, H(m)) / e(g1, sig)`.
pub fn miller(pk: &[u8; 96], hm: &[u8; 192], sig: &[u8; 192]) -> Option<Fp12Bytes> {
    let (pk, hm, sig) = (p1_from_uncompressed(pk)?, p2_from_uncompressed(hm)?, p2_from_uncompressed(sig)?);
    unsafe {
        let mut a = blst_fp12::default();
        blst_miller_loop(&mut a, &hm, &pk);
        let mut b = blst_fp12::default();
        blst_miller_loop(&mut b, &sig, blst_p1_affine_generator());
        blst_fp12_conjugate(&mut b);
        let mut f = blst_fp12::default();
        blst_fp12_mul(&mut f, &a, &b);
        Some(fp12_bytes(&f))
    }
}

/// Step two: the final exponentiation is one.
pub fn final_is_one(f: &Fp12Bytes) -> bool {
    let f = fp12_from(f);
    unsafe {
        let mut e = blst_fp12::default();
        blst_final_exp(&mut e, &f);
        blst_fp12_is_one(&e)
    }
}

pub fn pairing_check(pk: &[u8; 96], hm: &[u8; 192], sig: &[u8; 192]) -> bool {
    miller(pk, hm, sig).is_some_and(|f| final_is_one(&f))
}
