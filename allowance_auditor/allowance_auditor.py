#!/usr/bin/env python3
"""
allowance_auditor.py
====================

This tool audits ERC‑20 token allowances granted by an Ethereum wallet. It
connects directly to a JSON‑RPC endpoint via HTTP and requires only the
standard Python library and the `requests` package. It does not depend on
`web3.py` or other heavy dependencies, making it portable even in
restricted environments where external packages are unavailable.

The script scans all `Approval` events emitted by the target address to
discover which tokens and spenders are involved. It then fetches the
current allowance for each pair and categorises the result into CRITICAL,
MEDIUM or LOW risk based on simple heuristics. Results are printed in a
table and may optionally be exported to JSON or CSV.

See README.md for usage instructions and examples.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

import requests


# ----------------------------------------------------------------------------
# Constants and configuration
# ----------------------------------------------------------------------------

# Precomputed Keccak‑256 hashes and function selectors. These are taken from
# standard ERC‑20 definitions and do not require dynamic hashing. See
# https://docs.soliditylang.org/en/latest/abi-spec.html#function-selector
APPROVAL_TOPIC = (
    "0x8c5be1e5ebec7d5bd14f714f22dc3bd3f1fc0cf11088a7c6c1559617d7e604bb"
)
ALLOWANCE_SELECTOR = "0xdd62ed3e"  # keccak("allowance(address,address)")[:4]
DECIMALS_SELECTOR = "0x313ce567"   # keccak("decimals()")[:4]
SYMBOL_SELECTOR = "0x95d89b41"     # keccak("symbol()")[:4]

# Risk classification lists (lower‑case addresses). Extend these lists as
# DeFi evolves. Comments describe the contract associated with each address.
CRITICAL_SPENDERS: Dict[str, str] = {
    "0x7a250d5630b4cf539739df2c5dacab1e4afc886a": "Uniswap V2 Router",
    "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3 Router",
    "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f": "SushiSwap Router",
    "0x1111111254fb6c44bac0bed2854e76f90643097d": "1inch Router",
    "0x7d2768de32b0b80b7a3454c06bdac139dff81b6c": "Aave LendingPoolV2",
    "0xb1f2cde150c7a8f527ae434f5a8447c0988efb5e": "Curve Router",
    "0x8731d54e9d02c286767d56ac03e8037c07e01e98": "Stargate Router",
    "0x4f9a3f07c391e30f00c6c7c38367ef2f9f0a60bb": "Arbitrum Bridge",
}

KNOWN_SAFE_SPENDERS: Dict[str, str] = {
    "0x000000000000000000000000000000000000dead": "Burn Address",
}

# Unlimited threshold (2**255). Values equal or above this are treated as
# "unlimited" approvals.
UNLIMITED_THRESHOLD = 2 ** 255

logger = logging.getLogger("allowance_auditor")


# ----------------------------------------------------------------------------
# Helper classes and functions
# ----------------------------------------------------------------------------

class EthereumRPC:
    """A minimal JSON‑RPC client for Ethereum nodes.

    This class provides a simple interface to send JSON‑RPC requests to an
    Ethereum node. It avoids external dependencies by using the requests
    library directly. See https://ethereum.org/en/developers/docs/apis/json-rpc/
    for the list of supported methods.
    """

    def __init__(self, url: str) -> None:
        self.url = url
        self.session = requests.Session()
        self._id_counter = 0

    def _rpc(self, method: str, params: list) -> dict:
        self._id_counter += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._id_counter,
            "method": method,
            "params": params,
        }
        try:
            response = self.session.post(self.url, json=payload, timeout=30)
        except Exception as e:
            raise RuntimeError(f"RPC connection error: {e}")
        if response.status_code != 200:
            raise RuntimeError(
                f"RPC HTTP {response.status_code}: {response.text[:200]}"
            )
        data = response.json()
        if "error" in data and data["error"]:
            raise RuntimeError(
                f"RPC error {data['error'].get('code')}: {data['error'].get('message')}"
            )
        return data["result"]

    def block_number(self) -> int:
        """Return the latest block number."""
        result = self._rpc("eth_blockNumber", [])
        return int(result, 16)

    def get_logs(self, log_filter: dict) -> List[dict]:
        """Return event logs matching the provided filter."""
        return self._rpc("eth_getLogs", [log_filter])

    def eth_call(self, to: str, data: str) -> str:
        """Perform a call without creating a transaction and return raw hex data."""
        call_obj = {"to": to, "data": data}
        result = self._rpc("eth_call", [call_obj, "latest"])
        return result


def clean_address(addr: str) -> str:
    """Normalise an Ethereum address to lower‑case without the 0x prefix."""
    if addr.startswith("0x"):
        addr = addr[2:]
    return addr.lower()


def pad_hex(value: str, length: int = 64) -> str:
    """Left pad a hex string (without 0x) with zeros to the specified length."""
    return value.rjust(length, "0")


def build_call_data(function_selector: str, *args: str) -> str:
    """Construct call data for a function selector and address arguments.

    All arguments should be hex strings without the `0x` prefix. They will be
    left padded to 32 bytes (64 hex chars) as required by the ABI. The
    returned call data includes the 0x prefix.
    """
    encoded = function_selector[2:]
    for arg in args:
        encoded += pad_hex(arg)
    return "0x" + encoded


def parse_int256(data: str) -> int:
    """Decode a hex string returned from eth_call into an integer.

    The data string includes the 0x prefix and contains one or more 32‑byte
    ABI‑encoded values. This function returns the integer value of the first
    32‑byte segment.
    """
    if data.startswith("0x"):
        data = data[2:]
    if len(data) < 64:
        return 0
    return int(data[:64], 16)


@dataclass
class Allowance:
    token: str
    spender: str
    value: int
    token_symbol: str
    token_decimals: int
    risk_level: str

    def readable_amount(self) -> str:
        """Return the human friendly amount based on token decimals."""
        try:
            return f"{self.value / (10 ** self.token_decimals):.4f}"
        except Exception:
            return str(self.value)

    def as_dict(self) -> Dict:
        """Return a dict for export/serialization."""
        return {
            "token": self.token,
            "token_symbol": self.token_symbol,
            "spender": self.spender,
            "spender_label": CRITICAL_SPENDERS.get(
                self.spender, KNOWN_SAFE_SPENDERS.get(self.spender, "Unknown")
            ),
            "allowance": str(self.value),
            "allowance_readable": self.readable_amount(),
            "risk_level": self.risk_level,
        }


def determine_risk(allowance_value: int, spender: str) -> str:
    """Assign a risk level based on allowance amount and spender address."""
    # Normalise spender to lower‑case with 0x prefix for comparison
    spender_lc = spender.lower()
    unlimited = allowance_value >= UNLIMITED_THRESHOLD
    if unlimited and spender_lc in CRITICAL_SPENDERS:
        return "CRITICAL"
    if unlimited and spender_lc not in CRITICAL_SPENDERS:
        return "MEDIUM"
    if spender_lc in CRITICAL_SPENDERS:
        return "MEDIUM"
    if spender_lc in KNOWN_SAFE_SPENDERS:
        return "LOW"
    return "MEDIUM" if allowance_value > 0 else "LOW"


def get_token_metadata(rpc: EthereumRPC, token: str) -> Tuple[str, int]:
    """Retrieve symbol and decimals for a token via eth_call.

    Falls back to defaults if the call fails or returns an empty result.
    """

    symbol = token
    decimals = 18
    # symbol
    try:
        data = rpc.eth_call(token, SYMBOL_SELECTOR)
        # ABI‑encoded strings start with offset 32 bytes; for simple strings up to
        # 32 bytes the data after padding contains the string. We'll attempt to
        # decode ASCII characters and strip null bytes. If decoding fails the
        # fallback will be used.
        if data and len(data) >= 130:  # 0x + 32 bytes offset + length + padded string
            # The string length is encoded in bytes 64–96
            length = int(data[66:130], 16)
            hex_string = data[130:130 + length * 2]
            bytes_string = bytes.fromhex(hex_string)
            symbol = bytes_string.decode("utf‑8", errors="ignore")
    except Exception:
        pass
    # decimals
    try:
        data = rpc.eth_call(token, DECIMALS_SELECTOR)
        decimals = parse_int256(data)
    except Exception:
        pass
    return (symbol, decimals)


def get_approval_logs(
    rpc: EthereumRPC,
    owner: str,
    from_block: int = 0,
    to_block: Optional[int] = None,
    batch_size: int = 10000,
) -> Iterable[dict]:
    """Yield Approval event logs for the owner between block ranges.

    The function splits the range into batches to avoid RPC provider limits.
    Filters by the Approval topic and the owner topic (the second indexed
    parameter).
    """
    latest = to_block if to_block is not None else rpc.block_number()
    owner_topic = "0x" + pad_hex(clean_address(owner))
    start = from_block
    while start <= latest:
        end = min(start + batch_size - 1, latest)
        log_filter = {
            "fromBlock": hex(start),
            "toBlock": hex(end),
            "topics": [APPROVAL_TOPIC, owner_topic],
        }
        try:
            logs = rpc.get_logs(log_filter)
        except Exception as exc:
            err_msg = str(exc)
            # If there are too many results or provider errors, halve the batch size.
            if (
                "query returned more than" in err_msg
                or "limit" in err_msg.lower()
            ) and batch_size > 100:
                logger.warning(
                    f"Too many logs in batch {start}-{end}; reducing batch size to {batch_size//2}"
                )
                # Recurse with smaller batch size for this segment
                for log in get_approval_logs(
                    rpc, owner, start, end, batch_size // 2
                ):
                    yield log
                start = end + 1
                continue
            # Other RPC errors – log and abort this batch
            logger.error(
                f"Error fetching logs for block range {start}-{end}: {err_msg}"
            )
            start = end + 1
            continue
        for log in logs:
            yield log
        start = end + 1


def decode_approval_log(log: dict) -> Tuple[str, str, int]:
    """Decode Approval log into (token, spender, amount).

    Log fields are hex strings. The spender is the third topic and is
    represented as a 32‑byte value; we take the lower 40 hex chars (20 bytes)
    as the address. The amount is in `data` field.
    """
    token = log.get("address", "0x0").lower()
    topics = log.get("topics", [])
    if len(topics) < 3:
        return (token, "0x0", 0)
    spender_topic = topics[2]
    if isinstance(spender_topic, dict) and "0x" in spender_topic:
        spender_hex = spender_topic["0x"]
    else:
        spender_hex = spender_topic
    # remove 0x and take last 40 chars
    if spender_hex.startswith("0x"):
        spender_hex = spender_hex[2:]
    spender_addr = "0x" + spender_hex[-40:]
    # amount
    amount_hex = log.get("data", "0x0")
    amount = int(amount_hex, 16) if amount_hex else 0
    return (token, spender_addr.lower(), amount)


def fetch_allowance(
    rpc: EthereumRPC, token: str, owner: str, spender: str
) -> int:
    """Fetch the current allowance for a given token/owner/spender."""
    call_data = build_call_data(
        ALLOWANCE_SELECTOR, clean_address(owner), clean_address(spender)
    )
    try:
        data = rpc.eth_call(token, call_data)
        return parse_int256(data)
    except Exception as e:
        logger.warning(
            f"Failed to fetch allowance for token {token}, spender {spender}: {e}"
        )
        return 0


def analyse_allowances(
    rpc: EthereumRPC,
    owner: str,
    from_block: int = 0,
    to_block: Optional[int] = None,
) -> List[Allowance]:
    """Scan logs and return current allowances with risk classification."""
    allowances: List[Allowance] = []
    seen: set[Tuple[str, str]] = set()
    logger.info("Scanning approval logs to identify token/spender pairs...")
    for log in get_approval_logs(rpc, owner, from_block, to_block):
        token, spender, _ = decode_approval_log(log)
        pair = (token, spender)
        if pair not in seen:
            seen.add(pair)
    logger.info(f"Found {len(seen)} unique token/spender pairs")
    # Fetch current allowance and token metadata
    for token, spender in seen:
        value = fetch_allowance(rpc, token, owner, spender)
        if value == 0:
            continue
        symbol, decimals = get_token_metadata(rpc, token)
        risk = determine_risk(value, spender)
        allowances.append(
            Allowance(
                token=token,
                spender=spender,
                value=value,
                token_symbol=symbol,
                token_decimals=decimals,
                risk_level=risk,
            )
        )
    return allowances


def print_table(allowances: List[Allowance]) -> None:
    """Print a simple table of allowances to stdout."""
    if not allowances:
        print("No non‑zero allowances found.")
        return
    # Determine column widths
    headers = ["Token", "Spender", "Allowance", "Readable", "Risk"]
    rows: List[List[str]] = []
    for a in allowances:
        # normalise spender to lower‑case with 0x prefix for dictionary lookups
        spender_key = a.spender.lower()
        spender_label = CRITICAL_SPENDERS.get(
            spender_key, KNOWN_SAFE_SPENDERS.get(spender_key, "Unknown")
        )
        rows.append([
            f"{a.token_symbol}\n{a.token}",
            f"{spender_label}\n{a.spender}",
            str(a.value),
            a.readable_amount(),
            a.risk_level,
        ])
    # Compute width for each column
    col_widths = [len(h) for h in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            for line in cell.split("\n"):
                col_widths[idx] = max(col_widths[idx], len(line))
    # Print header
    sep_line = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"
    print(sep_line)
    header_line = "|" + "|".join(
        f" {headers[i].ljust(col_widths[i])} " for i in range(len(headers))
    ) + "|"
    print(header_line)
    print(sep_line)
    # Print rows
    for row in rows:
        # Determine the maximum number of lines in this row (due to \n)
        max_lines = max(cell.count("\n") + 1 for cell in row)
        lines_split = [cell.split("\n") + [""] * (max_lines - (cell.count("\n") + 1)) for cell in row]
        for i in range(max_lines):
            print(
                "|"
                + "|".join(
                    f" {lines_split[col][i].ljust(col_widths[col])} "
                    for col in range(len(headers))
                )
                + "|"
            )
        print(sep_line)
    # Summary
    critical = sum(1 for a in allowances if a.risk_level == "CRITICAL")
    medium = sum(1 for a in allowances if a.risk_level == "MEDIUM")
    low = sum(1 for a in allowances if a.risk_level == "LOW")
    print(f"Summary: {critical} critical, {medium} medium, {low} low risk approvals.")
    if critical > 0 or medium > 0:
        print(
            "\nRecommended: Consider revoking risky approvals using https://revoke.cash or a similar allowance manager."
        )


def export_allowances(allowances: List[Allowance], outfile: str) -> None:
    """Export allowances to JSON or CSV based on file extension."""
    fmt = None
    lower = outfile.lower()
    if lower.endswith(".json"):
        fmt = "json"
    elif lower.endswith(".csv"):
        fmt = "csv"
    else:
        raise ValueError("Unknown export format; use .json or .csv extension.")
    records = [a.as_dict() for a in allowances]
    if fmt == "json":
        with open(outfile, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2)
        logger.info(f"Exported {len(records)} records to {outfile}")
    else:
        # CSV
        if not records:
            # Write header only
            headers = [
                "token",
                "token_symbol",
                "spender",
                "spender_label",
                "allowance",
                "allowance_readable",
                "risk_level",
            ]
            with open(outfile, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=headers)
                writer.writeheader()
        else:
            headers = list(records[0].keys())
            with open(outfile, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=headers)
                writer.writeheader()
                writer.writerows(records)
        logger.info(f"Exported {len(records)} records to {outfile}")


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        description="Audit ERC‑20 allowances granted by a wallet and flag risky approvals."
    )
    parser.add_argument(
        "--address",
        required=True,
        help="Wallet address to audit (0x...).",
    )
    parser.add_argument(
        "--rpc",
        required=True,
        help="Ethereum JSON‑RPC endpoint (e.g. https://mainnet.infura.io/v3/<key>).",
    )
    parser.add_argument(
        "--from-block",
        type=int,
        default=0,
        help="Starting block for log scanning (default: 0).",
    )
    parser.add_argument(
        "--to-block",
        type=int,
        default=None,
        help="Ending block for scanning (default: latest).",
    )
    parser.add_argument(
        "--export",
        type=str,
        default=None,
        help="Export results to a file (.json or .csv).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging.",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s:%(name)s:%(message)s",
    )
    rpc = EthereumRPC(args.rpc)
    owner = args.address
    allowances = analyse_allowances(rpc, owner, args.from_block, args.to_block)
    print_table(allowances)
    if args.export:
        export_allowances(allowances, args.export)


if __name__ == "__main__":
    main()
