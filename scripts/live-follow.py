#!/usr/bin/env python3
"""Follow a public Ethereum chain's finality with Sextant's verifier, unattended,
and keep everything it read so anyone can replay it.

    scripts/live-follow.py init  sepolia|mainnet    checkpoint at the latest finalized header
    scripts/live-follow.py tick  sepolia|mainnet    fetch what is new, then replay
    scripts/live-follow.py loop  sepolia|mainnet... tick every EVERY seconds (default 384), forever

Each chain lives in evidence/live-run/<chain>/:

    genesis.json, fork_schedule.json    chain configuration (two beacon implementations agree)
    bootstrap-<slot>.json, .root         the checkpoint: the finalized header of the
                                         finality update at `init`, its bootstrap
                                         identical from both beacon nodes
    updates/<signature slot>-finality.json   every new finality update (one an epoch)
    updates/<signature slot>-period.json     the best update of each completed
                                         sync-committee period (the committee handoff),
                                         identical from both beacon nodes
    execution-headers.json               RLP execution headers (Gloas light-client
                                         headers name the block by hash; each RLP is
                                         checked to hash to it)
    fetch.jsonl                          one line per tick: what was read, from where,
                                         whether the second beacon node agreed
    verdicts.jsonl                       one line per update: host/src/bin/follow's
                                         verdict (applied or refused, and the store after)
    state.json                           the store the replay ends in

and evidence/live-run/LATEST holds every followed chain's latest verified
finalized header.

Nothing fetched is trusted: `follow` replays the whole directory from the
bootstrap through every update with sextant-core (the verifier the sextant_lc
guest runs: sync-committee BLS signature, finality and committee branches,
handoff rules), and an update it refuses changes nothing.
scripts/verify-live.sh reruns that replay and checks the finalized headers
against the beacon chain.
"""
import json
import os
import subprocess
import sys
import time
import urllib.request

from Crypto.Hash import keccak

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
BASE = os.path.join(REPO, "evidence", "live-run")
FOLLOW = os.environ.get("FOLLOW_BIN", os.path.join(REPO, "host", "target", "release", "follow"))
SLOTS_PER_PERIOD = 8192

NETWORKS = {
    "sepolia": {
        "chain_id": 11155111,
        "beacon": "http://unstable.sepolia.beacon-api.nimbus.team",
        "beacon2": "https://lodestar-sepolia.chainsafe.io",
        "exec": "https://ethereum-sepolia-rpc.publicnode.com",
    },
    "mainnet": {
        "chain_id": 1,
        "beacon": "http://unstable.mainnet.beacon-api.nimbus.team",
        "beacon2": "https://lodestar-mainnet.chainsafe.io",
        "exec": "https://ethereum-rpc.publicnode.com",
    },
}


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class Unavailable(Exception):
    pass


def get(url, tries=4):
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"accept": "application/json", "user-agent": "sextant-live"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read())
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(3 * (i + 1))
    raise Unavailable("GET %s: %s" % (url, last))


def rpc(url, method, params, tries=5):
    data = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, data=data, headers={"content-type": "application/json", "user-agent": "sextant-live"})
            with urllib.request.urlopen(req, timeout=60) as r:
                j = json.loads(r.read())
            if "error" in j:
                raise RuntimeError(j["error"])
            return j["result"]
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(3 * (i + 1))
    raise Unavailable("%s %s: %s" % (url, method, last))


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
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


def qty(s):
    v = int(s, 16)
    return v.to_bytes((v.bit_length() + 7) // 8, "big") if v else b""


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
            assert all(kk not in b for kk, _ in HEADER[i:]), "gap in header fields at %s" % k
            break
        items.append(f(b[k]))
    return rlp(items)


def period(slot):
    return int(slot) // SLOTS_PER_PERIOD


def dump(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1)
        f.write("\n")
    os.replace(tmp, path)


def same(a, b):
    """Compared as data, not text: Lodestar checksums addresses (EIP-55)."""
    return json.dumps(a, sort_keys=True).lower() == json.dumps(b, sort_keys=True).lower()


def chain_dir(name):
    return os.path.join(BASE, name)


def init(name):
    net, out = NETWORKS[name], chain_dir(name)
    if os.path.exists(out) and any(f.startswith("bootstrap-") for f in os.listdir(out)):
        raise SystemExit("%s already has a checkpoint" % out)
    os.makedirs(os.path.join(out, "updates"), exist_ok=True)
    B, B2 = net["beacon"], net["beacon2"]
    g, g2 = get(B + "/eth/v1/beacon/genesis"), get(B2 + "/eth/v1/beacon/genesis")
    assert g["data"]["genesis_validators_root"] == g2["data"]["genesis_validators_root"]
    dump(os.path.join(out, "genesis.json"), g)
    dump(os.path.join(out, "fork_schedule.json"), get(B2 + "/eth/v1/config/fork_schedule"))
    fins = [get(x + "/eth/v1/beacon/light_client/finality_update") for x in (B, B2)]
    # The older of the two finalized headers: both nodes know it.
    slot = min(int(f["data"]["finalized_header"]["beacon"]["slot"]) for f in fins)
    root = get("%s/eth/v1/beacon/headers/%d" % (B, slot))["data"]["root"]
    root2 = get("%s/eth/v1/beacon/headers/%d" % (B2, slot))["data"]["root"]
    assert root == root2, "the two beacon nodes disagree on the header at slot %d" % slot
    boot = get("%s/eth/v1/beacon/light_client/bootstrap/%s" % (B, root))
    boot2 = get("%s/eth/v1/beacon/light_client/bootstrap/%s" % (B2, root))
    assert same(boot["data"], boot2["data"]), "the two beacon nodes disagree on the bootstrap"
    assert int(boot["data"]["header"]["beacon"]["slot"]) == slot
    dump(os.path.join(out, "bootstrap-%d.json" % slot), boot)
    with open(os.path.join(out, "bootstrap-%d.root" % slot), "w") as f:
        f.write(root + "\n")
    log(out, {"time": now(), "event": "init", "checkpoint_slot": slot, "checkpoint_root": root,
              "sources": [B, B2], "agree": True})
    exec_headers(net, out)
    print("%s: checkpoint slot %d root %s" % (name, slot, root))


def log(out, obj):
    with open(os.path.join(out, "fetch.jsonl"), "a") as f:
        f.write(json.dumps(obj, sort_keys=True) + "\n")


def boot_slot(out):
    return int([f for f in os.listdir(out) if f.startswith("bootstrap-") and f.endswith(".json")][0][10:-5])


def exec_headers(net, out):
    """RLP of every execution block a Gloas light-client header names by hash only."""
    path = os.path.join(out, "execution-headers.json")
    rlps = json.load(open(path)) if os.path.exists(path) else {}
    hashes = set()
    for name in os.listdir(out):
        if name.startswith("bootstrap-") and name.endswith(".json"):
            h = json.load(open(os.path.join(out, name)))["data"]["header"]
            if "execution_block_hash" in h:
                hashes.add(h["execution_block_hash"])
    for name in os.listdir(os.path.join(out, "updates")):
        if not name.endswith(".json"):
            continue
        d = json.load(open(os.path.join(out, "updates", name)))["data"]
        for k in ("attested_header", "finalized_header"):
            if "execution_block_hash" in d[k]:
                hashes.add(d[k]["execution_block_hash"])
    new = 0
    for bh in sorted(hashes - set(rlps)):
        b = rpc(net["exec"], "eth_getBlockByHash", [bh, False])
        raw = header_rlp(b)
        assert "0x" + k256(raw).hex() == b["hash"] == bh, "header RLP does not hash to the block hash"
        rlps[bh] = "0x" + raw.hex()
        new += 1
    if new:
        dump(path, rlps)
    return new


def tick(name):
    net, out = NETWORKS[name], chain_dir(name)
    B, B2 = net["beacon"], net["beacon2"]
    ev = {"time": now(), "event": "tick"}
    try:
        fin = get(B + "/eth/v1/beacon/light_client/finality_update")
        try:
            fin2 = get(B2 + "/eth/v1/beacon/light_client/finality_update")
            ev["agree_finalized"] = same(fin["data"]["finalized_header"], fin2["data"]["finalized_header"])
        except Unavailable as e:
            ev["second_source"] = str(e)[:200]
        sig = int(fin["data"]["signature_slot"])
        ev["finality_signature_slot"] = sig
        ev["finalized_slot"] = int(fin["data"]["finalized_header"]["beacon"]["slot"])
        saved = []
        # The best update of every completed period since the checkpoint's: the handoffs.
        for p in range(period(boot_slot(out)), period(sig)):
            if any(f.endswith("-period.json") and f.startswith("p%06d-" % p) for f in os.listdir(os.path.join(out, "updates"))):
                continue
            q = "/eth/v1/beacon/light_client/updates?start_period=%d&count=1" % p
            u, u2 = get(B + q), get(B2 + q)
            assert len(u) == 1 and period(u[0]["data"]["attested_header"]["beacon"]["slot"]) == p
            if not same(u[0]["data"], u2[0]["data"]):
                ev.setdefault("period_disagree", []).append(p)
                continue  # retried next tick; a best update can still change near the boundary
            # Named so it sorts by signature slot among the finality updates.
            f = "%012d-period.json" % int(u[0]["data"]["signature_slot"])
            dump(os.path.join(out, "updates", f), {"data": u[0]["data"], "source": B + q, "second_source_identical": True,
                                                  "fetched": now(), "period": p})
            open(os.path.join(out, "updates", "p%06d-%s.marker" % (p, f[:12])), "w").close()
            saved.append(f)
        f = "%012d-finality.json" % sig
        fins = sorted(x for x in os.listdir(os.path.join(out, "updates")) if x.endswith("-finality.json"))
        last_fin = int(json.load(open(os.path.join(out, "updates", fins[-1])))["data"]["finalized_header"]["beacon"]["slot"]) if fins else -1
        # One finality update per newly finalized header (about one an epoch).
        if ev["finalized_slot"] > last_fin and not os.path.exists(os.path.join(out, "updates", f)):
            dump(os.path.join(out, "updates", f), {"data": fin["data"], "source": B + "/eth/v1/beacon/light_client/finality_update",
                                                  "fetched": now()})
            saved.append(f)
        ev["saved"] = saved
        ev["execution_headers_new"] = exec_headers(net, out)
    except (Unavailable, AssertionError) as e:
        ev["error"] = str(e)[:300]
    log(out, ev)
    replay(name)
    return ev


def replay(name):
    net, out = NETWORKS[name], chain_dir(name)
    rel = os.path.relpath(out, REPO)
    r = subprocess.run([FOLLOW, rel, str(net["chain_id"])], capture_output=True, text=True)
    if r.returncode != 0:
        log(out, {"time": now(), "event": "replay-failed", "stderr": r.stderr[-500:]})
        return
    lines = [json.loads(l) for l in r.stdout.splitlines() if l.startswith("{")]
    final = lines[-1]
    tmp = os.path.join(out, "verdicts.jsonl.tmp")
    with open(tmp, "w") as f:
        for l in lines[:-1]:
            f.write(json.dumps(l, sort_keys=True) + "\n")
    os.replace(tmp, os.path.join(out, "verdicts.jsonl"))
    st = dict(final["store"], applied=final["applied"], refused=final["refused"], replayed=now())
    dump(os.path.join(out, "state.json"), st)
    latest = os.path.join(BASE, "LATEST")
    cur = json.load(open(latest)) if os.path.exists(latest) else {}
    cur[name] = st
    dump(latest, cur)


def main():
    a = sys.argv[1:]
    if len(a) < 2 or a[0] not in ("init", "tick", "loop") or any(x not in NETWORKS for x in a[1:]):
        raise SystemExit(__doc__)
    if a[0] == "init":
        for n in a[1:]:
            init(n)
    elif a[0] == "tick":
        for n in a[1:]:
            print(json.dumps(tick(n)))
    else:
        every = int(os.environ.get("EVERY", "384"))
        while True:
            for n in a[1:]:
                try:
                    ev = tick(n)
                    print(n, json.dumps(ev), flush=True)
                except Exception as e:  # noqa: BLE001 - an unattended loop logs and goes on
                    log(chain_dir(n), {"time": now(), "event": "tick-crashed", "error": repr(e)[:300]})
                    print(n, "tick crashed:", repr(e)[:300], flush=True)
            time.sleep(every)


if __name__ == "__main__":
    main()
