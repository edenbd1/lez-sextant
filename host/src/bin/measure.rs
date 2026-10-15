//! User cycles of every step of sync-committee verification, in the RISC Zero
//! executor (r0vm 3.0.5): two BLS12-381 libraries (zkcrypto `bls12_381`,
//! supranational `blst`), each in a stock guest and in a guest with RISC
//! Zero's accelerated forks patched in; real mainnet data where it exists,
//! synthetic committees where the participation must be chosen.
//!
//! `cargo run --release --bin measure [-- --no-stock]`
//!
//! These are executor counts, the quantity the LEZ sequencer meters as gas;
//! development mode plays no part.

use sextant_core::bls::{self, KeyMode, Lib};
use sextant_core::lc::{self, AggMode, Opts, Prepared};
use sextant_core::{ssz, Op};
use sextant_host::*;

const CAP: u64 = 10_000_000;

fn pct(c: u64) -> String {
    format!("{:.1}%", c as f64 * 100.0 / CAP as f64)
}

struct Bench {
    acc: Vec<u8>,
    stock: Option<Vec<u8>>,
}

impl Bench {
    fn row(&self, label: &str, op: &Op) -> Run {
        let a = execute(&self.acc, op);
        assert!(a.report.ok.is_ok(), "{label}: accelerated guest refused: {:?}", a.report.ok);
        let s = self.stock.as_ref().map(|b| {
            let s = execute(b, op);
            assert_eq!(s.report.ok, a.report.ok, "{label}: the two guests disagree");
            s.user_cycles
        });
        let (sc, speed) = match s {
            Some(s) => (s.to_string(), format!("{:.1}x", s as f64 / a.user_cycles as f64)),
            None => ("not run".into(), String::new()),
        };
        println!(
            "| {label} | {sc} | {} | {speed} | {} | {} |",
            a.user_cycles,
            pct(a.user_cycles),
            if a.user_cycles <= CAP { "yes" } else { "**no**" },
        );
        a
    }

    fn stages(&self, label: &str, op: &Op) {
        let a = execute(&self.acc, op);
        assert!(a.report.ok.is_ok(), "{label}: {:?}", a.report.ok);
        println!("\n**{label}**: {} user cycles ({} segments)\n", a.user_cycles, a.segments);
        println!("| stage | cycles | share of the 10M cap |");
        println!("|---|---:|---:|");
        for w in a.report.marks.windows(2) {
            let d = w[1].1 - w[0].1;
            println!("| {} | {d} | {} |", w[1].0, pct(d));
        }
    }
}

fn header() {
    println!("| operation | stock guest | accelerated guest | speedup | share of 10M (accelerated) | fits one transaction (accelerated) |");
    println!("|---|---:|---:|---:|---:|---:|");
}

fn main() {
    let no_stock = std::env::args().any(|a| a == "--no-stock");
    let b = Bench { acc: guest_bin("accelerated"), stock: (!no_stock).then(|| guest_bin("stock")) };
    let m = mainnet();
    let steps = mainnet_steps(&m);
    let (store, u, c) = &steps[1]; // period 1882's update: 512 of 512 signed, carries the 1883 handoff
    let (store0, u0, c0) = &steps[0]; // period 1881's update: 511 of 512 signed
    let (sf, uf, cf) = &steps[3]; // a finality update of period 1884, no handoff
    let libs = [(Lib::Zkcrypto, "zkcrypto"), (Lib::Blst, "blst")];
    let opts = |lib, keys, agg| Opts { lib, keys, agg };

    println!("# sextant: measured user cycles (RISC Zero executor, r0vm 3.0.5)\n");
    println!(
        "Mainnet vectors: the update of sync-committee period 1882 (signature slot {}, {} of 512 signed) unless noted.\n",
        u.signature_slot,
        bls::participants(&u.bits)
    );

    // The pieces of one signature check, from the real update.
    let w = witness(c, &u.bits, AggMode::Subtract);
    let pk = bls::signing_key(Lib::Blst, c, &u.bits, &w, lc::FAST).unwrap();
    let epoch = (u.signature_slot - 1) / 32;
    let domain = ssz::sync_committee_domain(lc::fork_version(&m.cfg, epoch), &m.cfg.genesis_validators_root);
    let msg = ssz::signing_root(&ssz::beacon_header_root(&u.attested.beacon), &domain);
    let hm = bls::hash_to_g2(Lib::Blst, &msg);
    let sig = bls::decode_signature(Lib::Blst, &u.signature).unwrap();

    println!("## 1. The primitives\n");
    header();
    for (lib, name) in libs {
        b.row(
            &format!("(a) pairing check `e(pk,H(m)) = e(g1,sig)`, {name}"),
            &Op::Pairing { lib, pk: pk.to_vec(), hm: hm.to_vec(), sig: sig.to_vec() },
        );
    }
    for (lib, name) in libs {
        b.row(&format!("hash_to_curve G2 of the signing root, {name}"), &Op::HashToG2 { lib, msg });
    }
    for (lib, name) in libs {
        b.row(&format!("signature decompression + G2 subgroup check, {name}"), &Op::DecodeSignature { lib, sig: u.signature });
    }
    b.row("hash_tree_root of a 512-key SyncCommittee (SHA-256)", &Op::CommitteeRoot { committee: c.clone() });

    println!("\n## 2. Assembling the signing key (b)\n");
    header();
    for (lib, name) in libs {
        for (what, keys, agg) in [
            ("decompress + subgroup-check each key, sum", KeyMode::Checked, AggMode::Sum),
            ("decompress each key (no subgroup check), sum", KeyMode::Unchecked, AggMode::Sum),
            ("uncompressed witness checked against the committed bytes, sum", KeyMode::Witness, AggMode::Sum),
            ("committee aggregate minus non-signers (0 here)", KeyMode::Witness, AggMode::Subtract),
        ] {
            let o = opts(lib, keys, agg);
            b.row(&format!("512 of 512 (mainnet), {what}, {name}"), &Op::SigningKey { committee: c.clone(), bits: u.bits, witness: witness(c, &u.bits, agg), opts: o });
        }
    }
    b.row(
        "511 of 512 (mainnet, period 1881), aggregate minus 1 non-signer, blst",
        &Op::SigningKey { committee: c0.clone(), bits: u0.bits, witness: witness(c0, &u0.bits, AggMode::Subtract), opts: lc::FAST },
    );
    let syn = synthetic(342);
    for (lib, name) in libs {
        for (what, keys, agg) in [
            ("decompress + subgroup-check each key, sum", KeyMode::Checked, AggMode::Sum),
            ("uncompressed witness, sum", KeyMode::Witness, AggMode::Sum),
            ("aggregate minus 170 non-signers", KeyMode::Witness, AggMode::Subtract),
        ] {
            let o = opts(lib, keys, agg);
            b.row(
                &format!("342 of 512 (synthetic, the 2/3 floor), {what}, {name}"),
                &Op::SigningKey { committee: syn.committee.clone(), bits: syn.bits, witness: witness(&syn.committee, &syn.bits, agg), opts: o },
            );
        }
    }
    for (lib, name) in libs {
        let o = opts(lib, KeyMode::Witness, AggMode::Subtract);
        b.row(
            &format!("FastAggregateVerify, 342 of 512 (synthetic), witness + aggregate minus non-signers, {name}"),
            &Op::FastAggregateVerify { committee: syn.committee.clone(), bits: syn.bits, witness: witness(&syn.committee, &syn.bits, AggMode::Subtract), opts: o, msg: syn.msg, sig: syn.sig },
        );
    }

    println!("\n## 3. A whole LightClientUpdate in one session (c)\n");
    header();
    let upd = |store: &sextant_core::Store, u: &sextant_core::Update, c: &sextant_core::SyncCommittee, o: Opts| Op::Update {
        cfg: m.cfg.clone(),
        store: store.clone(),
        update: u.clone(),
        committee: c.clone(),
        witness: witness(c, &u.bits, o.agg),
        opts: o,
    };
    for (lib, name) in libs {
        b.row(&format!("period 1882 with handoff, naive (decompress + check 512 keys, sum), {name}"), &upd(store, u, c, opts(lib, KeyMode::Checked, AggMode::Sum)));
        b.row(&format!("period 1882 with handoff, witness + aggregate minus non-signers, {name}"), &upd(store, u, c, opts(lib, KeyMode::Witness, AggMode::Subtract)));
    }
    b.row("period 1881 with handoff (511 signed), fast path, blst", &upd(store0, u0, c0, lc::FAST));
    b.row(&format!("period 1884 finality update, no handoff ({} signed), fast path, blst", bls::participants(&uf.bits)), &upd(sf, uf, cf, lc::FAST));

    println!("\n## 4. The same update split into three steps (blst, the program's design)\n");
    header();
    let prep = |store: &sextant_core::Store, u: &sextant_core::Update, c: &sextant_core::SyncCommittee| Op::Prepare {
        cfg: m.cfg.clone(),
        store: store.clone(),
        update: u.clone(),
        committee: c.clone(),
        witness: witness(c, &u.bits, AggMode::Subtract),
        opts: lc::FAST,
    };
    let r = b.row("step 1 `prepare`, period 1882 with handoff: every check but the pairing", &prep(store, u, c));
    b.row(&format!("step 1 `prepare`, period 1884 finality update, no handoff ({} signed)", bls::participants(&uf.bits)), &prep(sf, uf, cf));
    let p: Prepared = borsh::from_slice(r.report.ok.as_ref().unwrap()).unwrap();
    let r = b.row("step 2 `miller`: the two Miller loops, product into one Fp12", &Op::Miller { pk: p.pk.clone(), hm: p.hm.clone(), sig: p.sig.clone() });
    b.row("step 3 `finish`: final exponentiation, compare to one", &Op::FinalExp { f: r.report.ok.unwrap() });
    b.row(
        "instance bootstrap from the checkpoint (committee root + branch)",
        &Op::Bootstrap { root: m.checkpoint, header: m.boot_header.clone(), committee: m.boot_committee.clone(), branch: m.boot_branch.clone() },
    );

    println!("\n## 5. The consumer side: inclusion under a finalized header\n");
    header();
    let fin = lc::apply_update(&m.cfg, sf, uf, cf, &witness(cf, &uf.bits, AggMode::Subtract), lc::FAST, &mut |_| {}).unwrap();
    let wp = weth_proof();
    b.row(
        &format!(
            "account + storage slot (WETH `balanceOf`), {} + {} nodes, Keccak",
            wp.account_proof.len(),
            wp.storage_proof.len()
        ),
        &Op::StorageProof { state_root: fin.finalized_execution_state_root, proof: wp },
    );
    for tx in [2u64, 0] {
        let rp = receipt_proof(tx);
        let bytes: usize = rp.proof.iter().map(Vec::len).sum();
        b.row(
            &format!("receipt + log 0 (tx {tx} of block {}), {} nodes, {bytes} bytes", fin.finalized_block_number, rp.proof.len()),
            &Op::ReceiptProof { receipts_root: fin.finalized_receipts_root, proof: rp },
        );
    }

    println!("\n## 6. Stage breakdowns (accelerated guest)");
    for (lib, name) in libs {
        b.stages(&format!("(a) pairing check, {name}"), &Op::Pairing { lib, pk: pk.to_vec(), hm: hm.to_vec(), sig: sig.to_vec() });
    }
    b.stages("(c) period 1882 with handoff, fast path, blst", &upd(store, u, c, lc::FAST));
    b.stages("(c) period 1882 with handoff, fast path, zkcrypto", &upd(store, u, c, opts(Lib::Zkcrypto, KeyMode::Witness, AggMode::Subtract)));
}
