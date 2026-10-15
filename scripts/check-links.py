#!/usr/bin/env python3
"""Every relative link in the repository's Markdown points at a file that exists.

usage: scripts/check-links.py   (from anywhere; exits non-zero on a dead link)
"""
import pathlib, re, sys

root = pathlib.Path(__file__).resolve().parent.parent
skip = {"target", "vendor", ".git"}
dead = checked = 0
for md in root.rglob("*.md"):
    if skip & set(md.relative_to(root).parts):
        continue
    for target in re.findall(r"\]\(([^)\s]+)\)", md.read_text()):
        if re.match(r"^[a-z]+:", target) or target.startswith("#"):
            continue
        checked += 1
        path = (md.parent / target.split("#")[0]).resolve()
        if not path.exists():
            dead += 1
            print(f"dead link in {md.relative_to(root)}: {target}")
print(f"{checked} relative links checked, {dead} dead")
sys.exit(1 if dead else 0)
