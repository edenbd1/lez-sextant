#!/usr/bin/env python3
"""Build the receipts trie of a mainnet block from its eth_getBlockReceipts
JSON, check that its root equals the block's receiptsRoot, and write the
Merkle-Patricia proof of one receipt.

    python3 scripts/receipt_proof.py vectors/mainnet/receipts.json \
        vectors/mainnet/block.json <tx index> vectors/mainnet/receipt-proof.json

Needs pycryptodome (Keccak-256).
"""
import json
import sys

from Crypto.Hash import keccak


def k256(b):
    h = keccak.new(digest_bits=256)
    h.update(b)
    return h.digest()


class Raw(bytes):
    """An already-encoded RLP item, embedded as is (an inline child node)."""


def rlp(x):
    if isinstance(x, Raw):
        return bytes(x)
    if isinstance(x, (bytes, bytearray)):
        x = bytes(x)
        if len(x) == 1 and x[0] < 0x80:
            return x
        return length(len(x), 0x80) + x
    body = b"".join(rlp(i) for i in x)
    return length(len(body), 0xC0) + body


def length(n, off):
    if n < 56:
        return bytes([off + n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([off + 55 + len(b)]) + b


def int_bytes(v):
    return b"" if v == 0 else v.to_bytes((v.bit_length() + 7) // 8, "big")


def hexb(s):
    return bytes.fromhex(s[2:])


def receipt(r):
    status = b"\x01" if int(r["status"], 16) == 1 else b""
    logs = [[hexb(l["address"]), [hexb(t) for t in l["topics"]], hexb(l["data"])] for l in r["logs"]]
    body = rlp([status, int_bytes(int(r["cumulativeGasUsed"], 16)), hexb(r["logsBloom"]), logs])
    t = int(r["type"], 16)
    return body if t == 0 else bytes([t]) + body


def nibbles(b):
    out = []
    for x in b:
        out += [x >> 4, x & 15]
    return out


def hp(nibs, leaf):
    flag = 2 if leaf else 0
    if len(nibs) % 2:
        nibs = [flag + 1] + nibs
    else:
        nibs = [flag, 0] + nibs
    return bytes(nibs[i] * 16 + nibs[i + 1] for i in range(0, len(nibs), 2))


def build(pairs, depth, path, target, proof):
    """Encode the node over `pairs`; append to `proof` the encodings of the
    hashed nodes on `target`'s path. Returns the node's encoding."""
    on_path = target[:depth] == path
    if len(pairs) == 1:
        k, v = pairs[0]
        enc = rlp([hp(k[depth:], True), v])
    else:
        cp = 0
        while all(len(k) > depth + cp for k, _ in pairs) and len({k[depth + cp] for k, _ in pairs}) == 1:
            cp += 1
        if cp:
            pre = pairs[0][0][depth : depth + cp]
            child = build(pairs, depth + cp, path + pre, target, proof)
            enc = rlp([hp(pre, False), ref(child)])
        else:
            slots = []
            for n in range(16):
                grp = [(k, v) for k, v in pairs if len(k) > depth and k[depth] == n]
                slots.append(ref(build(grp, depth + 1, path + [n], target, proof)) if grp else b"")
            val = [v for k, v in pairs if len(k) == depth]
            enc = rlp(slots + [val[0] if val else b""])
    if on_path and (len(enc) >= 32 or depth == 0):
        proof.append(enc)
    return enc


def ref(enc):
    return k256(enc) if len(enc) >= 32 else Raw(enc)


def main():
    receipts = json.load(open(sys.argv[1]))["result"]
    block = json.load(open(sys.argv[2]))["result"]
    idx = int(sys.argv[3])
    pairs = [(nibbles(rlp(int_bytes(i))), receipt(r)) for i, r in enumerate(receipts)]
    target = nibbles(rlp(int_bytes(idx)))
    proof = []
    root_enc = build(pairs, 0, [], target, proof)
    root = k256(root_enc)
    assert "0x" + root.hex() == block["receiptsRoot"], ("receipts root mismatch", root.hex(), block["receiptsRoot"])
    proof.reverse()  # root first
    out = {
        "block_number": int(block["number"], 16),
        "receipts_root": block["receiptsRoot"],
        "tx_index": idx,
        "tx_hash": receipts[idx]["transactionHash"],
        "proof": ["0x" + p.hex() for p in proof],
    }
    json.dump(out, open(sys.argv[4], "w"), indent=1)
    print(f"receipts root matches the block ({block['receiptsRoot']}); proof of tx {idx}: {len(proof)} nodes, {sum(len(p) for p in proof)} bytes")


main()
