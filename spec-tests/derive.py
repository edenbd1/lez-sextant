#!/usr/bin/env python3
"""What the single_merkle_proof vectors leave implicit, computed by the
consensus-specs pyspec at the pinned tag: the hash_tree_root of each test's
object (the root its proof must reach), and the field the proof's leaf is
derived from. sextant-core then derives the leaf itself and checks the
proof against that root at its own generalized index (src/lib.rs).

usage, from a consensus-specs checkout at v1.7.0-beta.4 after `make _pyspec`
(or `uv sync --all-extras && uv run python -m pysetup.generate_specs --all-forks`):

    uv run python <repo>/spec-tests/derive.py <repo>/spec-tests/vectors \
        > <repo>/spec-tests/derived/single_merkle_proof.json
"""
import importlib, json, pathlib, sys

import snappy

vectors = pathlib.Path(sys.argv[1])
out = []
for fork in ("electra", "fulu", "gloas"):
    s = importlib.import_module(f"eth_consensus_specs.{fork}.mainnet")
    base = vectors / "tests" / "mainnet" / fork / "light_client" / "single_merkle_proof"
    for typ in sorted(p.name for p in base.iterdir()):
        for case in sorted(p.name for p in (base / typ).iterdir()):
            raw = snappy.decompress((base / typ / case / "object.ssz_snappy").read_bytes())
            obj = getattr(s, typ).decode_bytes(raw)
            row = {"fork": fork, "type": typ, "case": case, "object_root": "0x" + s.hash_tree_root(obj).hex()}
            if case.startswith("current_sync_committee") or case.startswith("next_sync_committee"):
                c = obj.current_sync_committee if case.startswith("current") else obj.next_sync_committee
                row["committee"] = {"pubkeys": ["0x" + bytes(k).hex() for k in c.pubkeys], "aggregate_pubkey": "0x" + bytes(c.aggregate_pubkey).hex()}
            elif case.startswith("finality_root"):
                row["finalized_root"] = "0x" + bytes(obj.finalized_checkpoint.root).hex()
            elif case == "execution_block_hash_merkle_proof":
                row["block_hash"] = "0x" + bytes(obj.signed_execution_payload_bid.message.parent_block_hash).hex()
            elif case == "execution_merkle_proof":
                p = obj.execution_payload
                row["execution"] = {
                    "parent_hash": "0x" + bytes(p.parent_hash).hex(),
                    "fee_recipient": "0x" + bytes(p.fee_recipient).hex(),
                    "state_root": "0x" + bytes(p.state_root).hex(),
                    "receipts_root": "0x" + bytes(p.receipts_root).hex(),
                    "logs_bloom": "0x" + bytes(p.logs_bloom).hex(),
                    "prev_randao": "0x" + bytes(p.prev_randao).hex(),
                    "block_number": str(int(p.block_number)),
                    "gas_limit": str(int(p.gas_limit)),
                    "gas_used": str(int(p.gas_used)),
                    "timestamp": str(int(p.timestamp)),
                    "extra_data": "0x" + bytes(p.extra_data).hex(),
                    "base_fee_per_gas_le": "0x" + int(p.base_fee_per_gas).to_bytes(32, "little").hex(),
                    "block_hash": "0x" + bytes(p.block_hash).hex(),
                    "transactions_root": "0x" + s.hash_tree_root(p.transactions).hex(),
                    "withdrawals_root": "0x" + s.hash_tree_root(p.withdrawals).hex(),
                    "blob_gas_used": str(int(p.blob_gas_used)),
                    "excess_blob_gas": str(int(p.excess_blob_gas)),
                }
            else:
                raise SystemExit(f"unknown case {fork}/{typ}/{case}")
            out.append(row)
json.dump(out, sys.stdout, indent=1)
print()
