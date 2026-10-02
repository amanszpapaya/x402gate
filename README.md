# x402gate

A spending gate for AI agents that pay with [x402](https://github.com/x402-foundation/x402).

x402gate checks every payment an agent is about to make against a policy you write, and refuses anything the policy doesn't allow before it is signed. You set which networks, tokens and recipients are allowed, how much one payment may cost, and how much can be spent over time. Every decision is recorded in a tamper-evident audit log.

> **Use at your own risk.** x402gate is a personal research project. It has not had an independent security audit, and it may contain vulnerabilities or bugs that could lead to lost funds. It comes with no warranty of any kind. Run it on testnet first. On mainnet, use a dedicated wallet holding only what you are prepared to lose.

## Installation

You need Python 3.10 or newer.

```bash
git clone <repo-url> x402gate && cd x402gate
python -m venv .venv && source .venv/bin/activate
pip install .
```

This installs x402gate and its dependencies, including the official `x402` SDK, and adds an `x402gate` command. It was tested with `x402` 2.23.0 and 2.25.0.

## Usage

There are two ways to run it:

- **In-process firewall**: a few lines in your agent. Protects against an agent that has been tricked, for example by prompt injection.
- **Signer service**: the private key lives in a separate process the agent can't read. Use this when the agent's own code might be compromised.

### In-process firewall

Add a policy and install the firewall on the x402 client you already use:

```python
from x402gate.firewall import Firewall
from x402gate.policy import Policy

policy = Policy()
policy.add_network_allowlist({"eip155:<chain-id>"})              # the network you pay on
policy.add_asset_allowlist({"0xabcd...token"})                   # the token contract, e.g. USDC
policy.add_max_per_payment(10_000)               # $0.01 (USDC has 6 decimals)
policy.add_max_authorization_window(300)         # a signature stays valid for at most 5 minutes
policy.add_recipient_allowlist({"0xabcd...seller"})              # sellers you trust
policy.add_total_budget(1_000_000)               # $1.00 per rolling 24 hours

Firewall(policy).install(client)                 # `client` is your existing x402Client
```

That's it. Payments the policy allows go through as before. Refused ones raise the SDK's usual `PaymentError`, with the reason attached.

To keep budgets across restarts and keep the audit log on disk, pass a ledger and an audit file:

```python
from x402gate.audit import Audit
from x402gate.state import SpendState

Firewall(policy,
         state=SpendState(journal_path="data/ledger.jsonl"),
         audit=Audit(path="data/audit.jsonl")).install(client)
```

### Signer service

**1. Create a key and a config file** (`x402gate.toml`):

```bash
x402gate new-key --out key      # prints the address to fund
```

```toml
[service]
key_file = "key"
socket   = "run/signer.sock"
journal  = "data/ledger.jsonl"
audit    = "data/audit.jsonl"
rpc_urls = { "eip155:<chain-id>" = "https://rpc.example.com" }

[policy]
networks                 = ["eip155:<chain-id>"]
assets                   = ["0xabcd...token"]
max_per_payment          = 10000
max_authorization_window = 300
recipients               = ["0xabcd...seller"]
total_budget             = 1000000
```

**2. Check the config and start the service:**

```bash
x402gate check-config --config x402gate.toml
x402gate serve --config x402gate.toml
```

**3. Point the agent at it** instead of giving it a key:

```python
from x402.mechanisms.evm.exact.register import register_exact_evm_client
from x402gate.remote_signer import RemoteSigner

register_exact_evm_client(client, RemoteSigner(socket_path="run/signer.sock"))
```

For real protection, run the service as its own OS user so the agent can't read the key file. Never expose the socket on a network port.

### How spending is counted

A payment counts against the budget as soon as it is approved. If a server reports that a payment failed, x402gate doesn't take its word for it. The amount stays counted until the signature expires and the chain confirms it was never used. That's what `rpc_urls` is for.

## Policy rules

Amounts are in the token's smallest unit (for USDC, 10,000 = $0.01). The first four rules are required.

| Rule | Python / config key | What it stops |
|---|---|---|
| Network allowlist | `add_network_allowlist` / `networks` | paying on mainnet when you meant testnet |
| Token allowlist | `add_asset_allowlist` / `assets` | look-alike tokens, or spending other tokens in the wallet |
| Max per payment | `add_max_per_payment` / `max_per_payment` | one oversized payment |
| Signature lifetime | `add_max_authorization_window` / `max_authorization_window` | signatures that stay valid for days |
| Recipient allowlist | `add_recipient_allowlist` / `recipients` | paying someone you didn't approve |
| Total budget | `add_total_budget` / `total_budget` | draining the wallet in small payments |
| Per-payee budget | `add_recipient_budget` / `recipient_budget` | one payee taking too much |
| Rate limit | `add_velocity` / `[policy.velocity]` | rapid-fire payments |
| Custom rule | `add_custom` | anything else: a function that returns a reason to refuse, or `None` |

## Limitations

- The policy is a ceiling, not zero: an agent can still spend up to it.
- The in-process firewall is only as strong as the process it runs in. If the agent's own code can't be trusted, use the signer service.
- The signer service only signs `exact` (EIP-3009) payments.
- The RPC endpoints you configure are trusted to report the chain honestly. Two independent providers help.
- Budgets add up amounts across every token you allow, so allow one token per policy.

## Licence

MIT. See [LICENSE](LICENSE).
