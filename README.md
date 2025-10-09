# ERC‑20 Token Allowance Auditor

Have you ever wondered which contracts still have the ability to move your tokens? The ERC‑20 Token Allowance Auditor is a simple Python script that runs against an Ethereum node to find all `Approval` events for your wallet and tell you exactly who can spend your coins, how much they can spend, and how risky that approval is.

This script is intentionally lightweight: it uses only Python’s built‑in libraries and `requests` to talk to a JSON‑RPC endpoint. You don’t need `web3.py` or any heavy dependencies, which makes it easy to run on almost any machine.

## What it does

- **Finds token approvals** by scanning the blockchain for `Approval` events emitted by your address, then queries each token contract to see the current allowance.
- **Scores risk**: approvals to known DEX routers and bridges with “infinite” allowances are flagged as critical; approvals to unknown contracts are marked as medium risk; small, finite allowances to known contracts are considered low risk.
- **Shows results in a clear table** with token symbol, spender name (if known), raw allowance and a human‑readable amount.
- **Optionally exports** the results to JSON or CSV for further analysis.

## Getting started

1. Ensure you have Python 3.9 or newer installed.
2. Clone this repository or download the files.
3. Install the only required dependency:

```bash
pip install requests
```

(You can also install `flake8` if you want to lint the code.)

You’ll need access to an Ethereum JSON‑RPC endpoint from a provider like Infura or Alchemy, or your own node. The endpoint must support `eth_getLogs` and `eth_call`.

## Usage example

From the command line, run:

```bash
python allowance_auditor.py \
  --address 0xYourWalletAddress \
  --rpc https://your-node.example.com \
  --from-block 0 \
  --export allowances.json
```

Replace `0xYourWalletAddress` with the wallet you want to check, and set `--rpc` to your node’s RPC URL.

The script will print a table summarising each allowance and the associated risk. It will also suggest revoking risky approvals via a service like revoke.cash.

### Options

- `--from-block`: the first block to scan. Defaults to 0.
- `--to-block`: the last block to scan. Defaults to the latest block.
- `--export`: filename to save the results (`.json` or `.csv`).
- `--verbose`: turn on detailed logging.

## Risk categories

| Level     | Criteria                                                             | Suggested action                       |
|-----------|----------------------------------------------------------------------|----------------------------------------|
| Critical  | Unlimited allowance to a known high‑risk contract (DEXes, bridges)   | Revoke these approvals immediately.    |
| Medium    | Unlimited allowance to unknown addresses, or any allowance to risky contracts | Consider revoking or reducing them. |
| Low       | Finite allowances to known safe addresses                            | Probably safe, but review periodically |

The lists of known high‑risk and safe contracts live in `allowance_auditor.py` and can be updated as new projects emerge.

## Contributing

Feedback and pull requests are welcome! If you add a new feature, please include a corresponding test in `tests/`.
