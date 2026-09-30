#!/usr/bin/env python3
"""Compare a clean pinned Solidity rebuild with the artifacts used by T6 genesis."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read {path}: {exc}")


def norm_hex(value) -> str:
    if not isinstance(value, str):
        fail("compiled bytecode field is missing or not text")
    return value.removeprefix("0x").lower()


def normalized_layout(layout):
    if not isinstance(layout, dict):
        fail("compiled storage layout is missing")
    types = {}
    for key, value in layout.get("types", {}).items():
        types[key] = {
            field: value.get(field)
            for field in ("encoding", "label", "numberOfBytes")
            if field in value
        }
        if "members" in value:
            types[key]["members"] = [
                {field: member.get(field) for field in ("label", "slot", "offset", "type")}
                for member in value["members"]
            ]
    return {
        "storage": [
            {field: item.get(field) for field in ("label", "slot", "offset", "type")}
            for item in layout.get("storage", [])
        ],
        "types": types,
    }


def compare(name: str, published: dict, compiled: dict) -> None:
    if published.get("abi") != compiled.get("abi"):
        fail(f"{name}: ABI differs from the pinned Solidity rebuild")
    if norm_hex(published.get("bytecode")) != norm_hex(compiled.get("bytecode", {}).get("object")):
        fail(f"{name}: creation bytecode differs from the pinned Solidity rebuild")
    if norm_hex(published.get("runtime")) != norm_hex(compiled.get("deployedBytecode", {}).get("object")):
        fail(f"{name}: runtime bytecode differs from the pinned Solidity rebuild")
    published_immutables = published.get("immutableReferences") or {}
    compiled_immutables = compiled.get("deployedBytecode", {}).get("immutableReferences") or {}
    if published_immutables != compiled_immutables:
        fail(f"{name}: immutable references differ from the pinned Solidity rebuild")
    if normalized_layout(published.get("storageLayout")) != normalized_layout(compiled.get("storageLayout")):
        fail(f"{name}: storage layout differs from the pinned Solidity rebuild")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--bft-root", required=True, type=Path)
    parser.add_argument("--contracts-root", required=True, type=Path)
    parser.add_argument("--contracts-commit", required=True)
    args = parser.parse_args()

    manifest = read_json(args.manifest)
    manifest_contracts = manifest.get("contracts", [])
    if len(manifest_contracts) != 4:
        fail(f"placeholder manifest has {len(manifest_contracts)} contracts, expected four")
    for contract in manifest_contracts:
        if contract.get("sourceCommit", "").lower() != args.contracts_commit.lower():
            fail(f"{contract.get('name')}: manifest sourceCommit is not {args.contracts_commit}")
        rel = Path(contract["artifact"])
        if rel.is_absolute() or ".." in rel.parts:
            fail(f"{contract.get('name')}: unsafe artifact path {rel}")
        published_path = args.bft_root / "registrygenesis" / rel
        digest = hashlib.sha256(published_path.read_bytes()).hexdigest()
        if digest.lower() != contract.get("sha256", "").lower():
            fail(f"{contract.get('name')}: manifest artifact SHA-256 does not match {published_path}")
        published = read_json(published_path)
        name = contract["name"]
        source_name = {
            "feeCollector": "FeeCollector",
            "wuct": "WUCT",
            "teamVesting": "ImmutableVestingVault",
            "ecosystemVesting": "ImmutableVestingVault",
        }[name]
        compiled_path = args.contracts_root / "out" / f"{source_name}.sol" / f"{source_name}.json"
        compare(name, published, read_json(compiled_path))
        print(f"PASS: {name} manifest artifact and clean pinned build match (sha256={digest})")

    embedded_path = args.bft_root / "registrygenesis" / "seal-registry-v1.json"
    embedded = read_json(embedded_path)
    compiled_registry = read_json(args.contracts_root / "out" / "SealRegistry.sol" / "SealRegistry.json")
    published_runtime = norm_hex(embedded.get("runtimeBytecode"))
    rebuilt_runtime = norm_hex(compiled_registry.get("deployedBytecode", {}).get("object"))
    if published_runtime != rebuilt_runtime:
        fail("SealRegistry runtime differs from the pinned Solidity rebuild")
    print(f"PASS: SealRegistry clean rebuild matches the genesis runtime (codeHash={embedded.get('codeHash')})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
