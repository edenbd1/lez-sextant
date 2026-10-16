#!/usr/bin/env python3
"""Markdown table of a run's transactions, each linked to the block explorer.

usage: scripts/links.py <explorer-url> <manifest>   (markdown on stdout)
"""
import sys

explorer, manifest = sys.argv[1].rstrip("/"), sys.argv[2]
lines = open(manifest).read().splitlines()
for l in lines:
    if l.startswith("# program "):
        _, _, header, image = l.split()[:4]
        print(f"Program header [`{header}`]({explorer}/account/{header}), ImageID `{image}`.\n")
deploys = [l.split()[2:4] for l in lines if l.startswith("# deploy ")]
if deploys:
    print("| deployment | transaction |\n|---|---|")
    for what, h in deploys:
        print(f"| {what} | [`{h[:16]}…`]({explorer}/transaction/{h}) |")
    print()
print("| step | expected | verdict | block | transaction | pre-check | charged gas / limit |\n|---|---|---|---:|---|---|---:|")
for l in lines:
    if l.startswith("#") or not l.strip():
        continue
    label, expected, verdict, block, tx, attempts, pre, limit, charged = (l.split("\t") + [""] * 9)[:9]
    cell = f"[`{tx[:16]}…`]({explorer}/transaction/{tx})" if len(tx) == 64 else "not sent"
    print(f"| {label} | {expected} | {verdict} | {block or '-'} | {cell} | {pre} | {charged} / {limit} |")
