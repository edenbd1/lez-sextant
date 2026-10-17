#!/usr/bin/env python3
"""Fetch a light-client vector set for a public Ethereum chain, read-only, from
public endpoints, and check it for internal consistency before writing it.

    python3 scripts/fetch-vectors.py sepolia vectors/sepolia
    python3 scripts/fetch-vectors.py hoodi   vectors/hoodi
    python3 scripts/fetch-vectors.py sepolia vectors/sepolia --headers
    python3 scripts/fetch-vectors.py sepolia vectors/sepolia-gloas-fork --range 1377 4
    python3 scripts/fetch-vectors.py hoodi   vectors/hoodi --checkpoint-block

`--headers` only (re)builds execution-headers.json for the light-client files
already in the directory. `--range START COUNT` writes a bootstrap at period
START and the best updates of COUNT periods (no finality update, no proofs):
Sepolia 1377-1380 crosses the Gloas fork (epoch 353,024, period 1379).
`--checkpoint-block` writes `block-<n>/` for the execution block the
directory's bootstrap commits to, the proofs a consumer attests with as soon
as `Init` has run (the layout of vectors/mainnet/block-26170219/): block.json,
receipts.json, the receipt proof of the first transaction whose first log is
an ERC-20 `Transfer` (else of the first with a log), and the EIP-2935 history slot's eth_getProof if the
proof endpoint still serves the block.

What it writes (the layout of vectors/mainnet/, plus the execution header):

    genesis.json, fork_schedule.json     chain configuration (beacon API)
    bootstrap-<slot>.json, .root          LightClientBootstrap at the first slot
                                          of period P-3 (the checkpoint)
    updates-<P-3>-<P-1>.json              best LightClientUpdate of each period:
                                          three sync-committee handoffs
    finality_update.json                  a finality update in period P
    block.json                            the execution block the finality
                                          update's finalized header commits to
    header.rlp                            that block's RLP header (Gloas light
                                          client headers carry only its hash)
    receipts.json                         eth_getBlockReceipts of that block
    getproof-history.json                 eth_getProof of the EIP-2935 history
                                          contract's slot for block N-1 (whose
                                          value must be block N's parentHash)
    getproof-weth.json                    (sepolia) WETH9 balanceOf[holder]
    receipt-proof-tx<i>.json              receipt proofs (scripts/receipt_proof.py)
    execution-headers.json                {block hash: RLP header} for every
                                          Gloas light-client header above
    SOURCES.txt                           which endpoint served what, and when

Updates are fetched from two independent beacon implementations and must be
identical (up to hex case). The block's RLP header must hash to the block hash, and the
receipts must rebuild the block's receiptsRoot (receipt_proof.py checks it).
Needs pycryptodome (Keccak-256), like receipt_proof.py.
"""
import json
import os
import subprocess
import sys
import time
import urllib.request

from Crypto.Hash import keccak

SLOTS_PER_PERIOD = 8192
HISTORY = "0x0000F90827F1C53a10cb7A02335B175320002935"  # EIP-2935
HISTORY_WINDOW = 8191

NETWORKS = {
    "sepolia": {
        "chain_id": 11155111,
        # Nimbus serves historical bootstraps; Lodestar only recent ones but
        # gives a second, independent copy of every update.
        "beacon": "http://unstable.sepolia.beacon-api.nimbus.team",
        "beacon2": "https://lodestar-sepolia.chainsafe.io",
        "exec": "https://ethereum-sepolia-rpc.publicnode.com",
        # A free endpoint with an eth_getProof window that reaches the
        # finalized block (publicnode's does not).
        "proof": "https://sepolia.gateway.tenderly.co",
        # publicnode has pruned the receipts of blocks a few days old.
        "receipts": "https://sepolia.gateway.tenderly.co",
        "weth": "0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14",
    },
    "hoodi": {
        "chain_id": 560048,
        # Lighthouse serves historical bootstraps here; Lodestar is the second copy.
        "beacon": "https://ethereum-hoodi-beacon-api.publicnode.com",
        "beacon2": "https://lodestar-hoodi.chainsafe.io",
        "exec": "https://ethereum-hoodi-rpc.publicnode.com",
        "proof": "https://hoodi.gateway.tenderly.co",
        "weth": None,
    },
}

LOG = []


def get(url, tries=5):
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"accept": "application/json", "user-agent": "sextant-fetch"})
            with urllib.request.urlopen(req, timeout=60) as r:
                body = r.read()
            LOG.append("GET  %s" % url)
            return json.loads(body)
        except Exception as e:  # noqa: BLE001 - retry anything, report the last
            last = e
            time.sleep(2 * (i + 1))
    raise SystemExit("GET %s failed: %s" % (url, last))


def rpc(url, method, params, tries=6):
    data = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    for i in range(tries):
        try:
            req = urllib.request.Request(url, data=data, headers={"content-type": "application/json", "user-agent": "sextant-fetch"})
            with urllib.request.urlopen(req, timeout=60) as r:
                j = json.loads(r.read())
            if "error" in j:
                raise RuntimeError(j["error"])
            LOG.append("RPC  %s %s %s" % (url, method, json.dumps(params)))
            return j
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(3 * (i + 1))
    raise SystemExit("%s %s failed: %s" % (method, url, last))


def k256(b):
    h = keccak.new(digest_bits=256)
    h.update(b)
    return h.digest()


def rlp(x):
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


def hb(s):
    return bytes.fromhex(s[2:]) if s.startswith("0x") else bytes.fromhex(s)


def qty(s):
    v = int(s, 16)
    return v.to_bytes((v.bit_length() + 7) // 8, "big") if v else b""


# Header fields in RLP order, by fork; optional trailing fields are present
# from the fork that introduced them (London ... Amsterdam).
HEADER = [
    ("parentHash", hb), ("sha3Uncles", hb), ("miner", hb), ("stateRoot", hb),
    ("transactionsRoot", hb), ("receiptsRoot", hb), ("logsBloom", hb),
    ("difficulty", qty), ("number", qty), ("gasLimit", qty), ("gasUsed", qty),
    ("timestamp", qty), ("extraData", hb), ("mixHash", hb), ("nonce", hb),
    ("baseFeePerGas", qty), ("withdrawalsRoot", hb), ("blobGasUsed", qty),
    ("excessBlobGas", qty), ("parentBeaconBlockRoot", hb), ("requestsHash", hb),
    ("blockAccessListHash", hb), ("slotNumber", qty),
]


def header_rlp(b):
    items = []
    for i, (k, f) in enumerate(HEADER):
        if k not in b:
            # every later field must be absent too
            assert all(kk not in b for kk, _ in HEADER[i:]), "gap in header fields at %s" % k
            break
        items.append(f(b[k]))
    return rlp(items)


def period(slot):
    return int(slot) // SLOTS_PER_PERIOD


def lc_block_hash(h):
    """The execution block hash a LightClientHeader commits to (Electra: in
    the payload header; Gloas: `execution_block_hash`)."""
    return h["execution_block_hash"] if "execution_block_hash" in h else h["execution"]["block_hash"]


def dump(out, name, obj):
    with open(os.path.join(out, name), "w") as f:
        json.dump(obj, f, indent=1)
        f.write("\n")


def chain_config(net, out):
    B, B2 = net["beacon"], net["beacon2"]
    genesis = get(B + "/eth/v1/beacon/genesis")
    assert get(B2 + "/eth/v1/beacon/genesis")["data"]["genesis_validators_root"] == genesis["data"]["genesis_validators_root"]
    dump(out, "genesis.json", genesis)
    dump(out, "fork_schedule.json", get(B2 + "/eth/v1/config/fork_schedule"))


def bootstrap(net, out, first):
    """The checkpoint: the first block of period `first` (walking forward past
    empty slots) and its LightClientBootstrap."""
    B = net["beacon"]
    for slot in range(first * SLOTS_PER_PERIOD, first * SLOTS_PER_PERIOD + 64):
        try:
            hdr = get("%s/eth/v1/beacon/headers/%d" % (B, slot), tries=1)
        except SystemExit:
            continue
        root = hdr["data"]["root"]
        boot = get("%s/eth/v1/beacon/light_client/bootstrap/%s" % (B, root), tries=2)
        break
    else:
        raise SystemExit("no bootstrap in the first 64 slots of period %d" % first)
    bslot = int(boot["data"]["header"]["beacon"]["slot"])
    dump(out, "bootstrap-%d.json" % bslot, boot)
    with open(os.path.join(out, "bootstrap-%d.root" % bslot), "w") as f:
        f.write(root + "\n")


def updates(net, out, first, count):
    """The best update of each period, from two beacon implementations that
    must agree."""
    q = "/eth/v1/beacon/light_client/updates?start_period=%d&count=%d" % (first, count)
    ups, ups2 = get(net["beacon"] + q), get(net["beacon2"] + q)
    # Compared as data, not text: Lodestar checksums addresses (EIP-55).
    same = json.dumps([u["data"] for u in ups]).lower() == json.dumps([u["data"] for u in ups2]).lower()
    assert same, "the two beacon nodes disagree on the best updates"
    assert [period(u["data"]["attested_header"]["beacon"]["slot"]) for u in ups] == list(range(first, first + count))
    dump(out, "updates-%d-%d.json" % (first, first + count - 1), ups)


def execution_headers(net, out):
    """Gloas light-client headers commit to an execution block by hash only.
    For every such header the vectors carry, the RLP block header that hashes
    to it (verified here), as `execution-headers.json` {hash: rlp}."""
    headers = []
    for name in sorted(os.listdir(out)):
        if name.startswith("bootstrap-") and name.endswith(".json"):
            headers.append(json.load(open(os.path.join(out, name)))["data"]["header"])
        elif (name.startswith("updates-") and name.endswith(".json")) or name == "finality_update.json":
            j = json.load(open(os.path.join(out, name)))
            for u in (j if isinstance(j, list) else [j]):
                headers += [u["data"]["attested_header"], u["data"]["finalized_header"]]
    hashes = sorted({h["execution_block_hash"] for h in headers if "execution_block_hash" in h})
    rlps = {}
    for bh in hashes:
        b = rpc(net["exec"], "eth_getBlockByHash", [bh, False])["result"]
        raw = header_rlp(b)
        assert "0x" + k256(raw).hex() == b["hash"] == bh, "header RLP does not hash to the block hash"
        rlps[bh] = "0x" + raw.hex()
    if rlps:
        dump(out, "execution-headers.json", rlps)
    return len(rlps)


TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


def checkpoint_block(net, out):
    """Proofs against the execution block of the directory's checkpoint."""
    here = os.path.dirname(os.path.abspath(__file__))
    boot = [n for n in os.listdir(out) if n.startswith("bootstrap-") and n.endswith(".json")]
    assert len(boot) == 1, "exactly one bootstrap in %s" % out
    bh = lc_block_hash(json.load(open(os.path.join(out, boot[0])))["data"]["header"])
    E = net["exec"]
    block = rpc(E, "eth_getBlockByHash", [bh, False])
    b = block["result"]
    raw = header_rlp(b)
    assert "0x" + k256(raw).hex() == b["hash"] == bh, "header RLP does not hash to the block hash"
    n = int(b["number"], 16)
    d = os.path.join(out, "block-%d" % n)
    os.makedirs(d, exist_ok=True)
    dump(d, "block.json", block)
    # Receipts first: free endpoints serve them for any block, while their
    # eth_getProof window (a few dozen blocks) is usually long past here.
    receipts = rpc(net.get("receipts", E), "eth_getBlockReceipts", [b["number"]])
    assert receipts["result"] and receipts["result"][0]["blockHash"] == bh, "receipts of another block"
    dump(d, "receipts.json", receipts)
    rs = receipts["result"]
    i = next((i for i, r in enumerate(rs) if r["logs"] and r["logs"][0]["topics"][:1] == [TRANSFER]), None)
    if i is None:
        i = next(i for i, r in enumerate(rs) if r["logs"] and r["logs"][0]["topics"])
    subprocess.run([sys.executable, os.path.join(here, "receipt_proof.py"), os.path.join(d, "receipts.json"),
                    os.path.join(d, "block.json"), str(i), os.path.join(d, "receipt-proof-tx%d.json" % i)], check=True)
    hslot = "0x%064x" % ((n - 1) % HISTORY_WINDOW)
    try:
        gp = rpc(net["proof"], "eth_getProof", [HISTORY, [hslot], {"blockHash": bh}], tries=2)
        assert gp["result"]["storageProof"][0]["value"].lower().lstrip("0x").rjust(64, "0") == b["parentHash"][2:].lower(), "EIP-2935 slot is not the parent hash"
        assert "0x" + k256(hb(gp["result"]["accountProof"][0])).hex() == b["stateRoot"], "proof is not under the block's state root"
        dump(d, "getproof-history.json", gp)
        name = "getproof-history.json"
    except SystemExit as e:
        name = "no eth_getProof: %s" % ("the proof endpoint's window is past this block" if "proof window" in str(e) else str(e)[-120:])
    sources(d, ["checkpoint execution block %d (%s), receipt proof for tx %d, %s" % (n, bh, i, name)])
    print("ok: %s checkpoint block %d, receipt tx %d, %s" % (sys.argv[1], n, i, name))


def sources(out, lines):
    with open(os.path.join(out, "SOURCES.txt"), "a") as f:
        f.write("fetched %s by scripts/fetch-vectors.py %s\n" % (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), " ".join(sys.argv[1:])))
        for line in lines + LOG:
            f.write(line + "\n")


def main():
    args = sys.argv[1:]
    if len(args) < 2 or args[0] not in NETWORKS:
        raise SystemExit(__doc__)
    net, out = NETWORKS[args[0]], args[1]
    os.makedirs(out, exist_ok=True)
    if args[2:3] == ["--headers"]:
        n = execution_headers(net, out)
        sources(out, ["execution headers: %d" % n])
        print("ok: %d execution headers" % n)
        return
    if args[2:3] == ["--checkpoint-block"]:
        checkpoint_block(net, out)
        return
    if args[2:3] == ["--range"]:
        first, count = int(args[3]), int(args[4])
        chain_config(net, out)
        bootstrap(net, out, first)
        updates(net, out, first, count)
        n = execution_headers(net, out)
        sources(out, ["checkpoint period %d, updates %d-%d, execution headers %d" % (first, first, first + count - 1, n)])
        print("ok: periods %d..%d, %d execution headers" % (first, first + count - 1, n))
        return
    here = os.path.dirname(os.path.abspath(__file__))
    B, B2 = net["beacon"], net["beacon2"]
    chain_config(net, out)

    # The fresher of the two finality updates: the proof window of a free
    # execution endpoint is a few dozen blocks behind the head.
    fins = [get(x + "/eth/v1/beacon/light_client/finality_update") for x in (B, B2)]
    fin = max(fins, key=lambda f: int(f["data"]["finalized_header"]["beacon"]["slot"]))
    P = period(fin["data"]["finalized_header"]["beacon"]["slot"])
    assert period(fin["data"]["signature_slot"]) == P, "finality update straddles a period boundary; retry in a few minutes"
    first = P - 3
    bootstrap(net, out, first)
    updates(net, out, first, 3)
    dump(out, "finality_update.json", fin)
    # The execution block the finalized header commits to; its proofs are
    # fetched first, while the block is still inside the proof window.
    E = net["exec"]
    bh = lc_block_hash(fin["data"]["finalized_header"])
    block = rpc(E, "eth_getBlockByHash", [bh, False])
    b = block["result"]
    raw = header_rlp(b)
    assert "0x" + k256(raw).hex() == b["hash"] == bh, "header RLP does not hash to the block hash"
    dump(out, "block.json", block)
    with open(os.path.join(out, "header.rlp"), "w") as f:
        f.write("0x" + raw.hex() + "\n")
    with open(os.path.join(out, "finalized-block.txt"), "w") as f:
        f.write(b["number"] + "\n")

    # eth_getProof at the block, named by hash (EIP-1898): free endpoints
    # refuse a block number this far behind the head but serve the hash.
    n = int(b["number"], 16)
    at = {"blockHash": bh}
    hslot = "0x%064x" % ((n - 1) % HISTORY_WINDOW)
    gp = rpc(net["proof"], "eth_getProof", [HISTORY, [hslot], at])
    assert "0x" + k256(hb(gp["result"]["accountProof"][0])).hex() == b["stateRoot"], "proof is not under the block's state root"
    assert gp["result"]["storageProof"][0]["value"].lower().lstrip("0x").rjust(64, "0") == b["parentHash"][2:].lower(), "EIP-2935 slot is not the parent hash"
    dump(out, "getproof-history.json", gp)
    if net["weth"]:
        # A recent WETH9 depositor; balanceOf lives at keccak(pad(holder) || pad(3)).
        logs = rpc(E, "eth_getLogs", [{"address": net["weth"], "fromBlock": hex(n - 500), "toBlock": b["number"],
                                       "topics": ["0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c"]}])["result"]
        holder = logs[-1]["topics"][1][-40:]
        slot = "0x" + k256(bytes(12) + bytes.fromhex(holder) + (3).to_bytes(32, "big")).hex()
        time.sleep(2)
        gw = rpc(net["proof"], "eth_getProof", [net["weth"], [slot], at])
        assert "0x" + k256(hb(gw["result"]["accountProof"][0])).hex() == b["stateRoot"], "proof is not under the block's state root"
        dump(out, "getproof-weth.json", gw)

    # Receipt proofs: the first receipt with a log, and the busiest one.
    receipts = rpc(E, "eth_getBlockReceipts", [b["number"]])
    dump(out, "receipts.json", receipts)
    rs = receipts["result"]
    with_logs = [i for i, r in enumerate(rs) if r["logs"]]
    picks = sorted({with_logs[0], max(with_logs, key=lambda i: len(rs[i]["logs"]))}) if with_logs else []
    for i in picks:
        subprocess.run([sys.executable, os.path.join(here, "receipt_proof.py"), os.path.join(out, "receipts.json"),
                        os.path.join(out, "block.json"), str(i), os.path.join(out, "receipt-proof-tx%d.json" % i)], check=True)

    nh = execution_headers(net, out)
    sources(out, ["checkpoint period %d, updates %d-%d, finality update period %d, execution block %d" % (first, first, first + 2, P, n),
                  "receipt proofs for tx %s" % picks, "execution headers: %d" % nh])
    print("ok: %s periods %d..%d, block %d, receipts %s" % (sys.argv[1], first, P, n, picks))


if __name__ == "__main__":
    main()
