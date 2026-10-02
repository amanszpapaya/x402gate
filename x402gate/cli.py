"""x402gate command line: new-key, check-config, serve, status, verify-audit."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from .config import Config, check_key_file_permissions


def cmd_new_key(args: argparse.Namespace) -> int:
    from eth_account import Account
    path = Path(args.out)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        print(f"error: {path} already exists; refusing to overwrite a key", file=sys.stderr)
        return 1
    account = Account.create()
    with os.fdopen(fd, "w") as fh:
        fh.write(account.key.hex() + "\n")
    print(f"wrote {path} (mode 600)")
    print(f"address: {account.address}")
    print("fund this address with only what you are prepared to lose; "
          "the balance is the hard limit.")
    return 0


def cmd_check_config(args: argparse.Namespace) -> int:
    config = Config.load(args.config)
    policy = config.build_policy()
    from .firewall import Firewall
    Firewall.check_minimum_policy(policy)
    account = config.load_account() if config.has_service else None
    # Report success only after every check has passed.
    print(f"config ok: {args.config}")
    print("\npolicy:")
    for rule in policy.rules():
        print(f"  - {rule['name']:26} {rule['description']}")
    if account is not None:
        print("\nservice:")
        print(f"  signer address : {account.address}")
        print(f"  key file       : {config.path('key_file')} (permissions ok)")
        print(f"  socket         : {config.path('socket')} (mode {oct(config.socket_mode)})")
        print(f"  ledger journal : {config.path('journal')}")
        print(f"  audit log      : {config.path('audit')} (strict={config.audit_strict})")
        if config.rpc_urls:
            print(f"  chain checks   : {', '.join(config.rpc_urls)}")
        else:
            print("  chain checks   : none — every signed authorization stays counted "
                  "until it ages out of the window")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from .audit import Audit
    from .signer_service import serve
    config = Config.load(args.config)
    os.umask(0o077)
    # Never seal new records onto a tampered chain; an operator must look first.
    if config.path("audit").exists():
        existing = Audit(path=config.path("audit"), strict=False)
        try:
            ok, problem = existing.verify()
        finally:
            existing.close()
        if not ok:
            print(f"error: audit chain at {config.path('audit')} is broken ({problem}); "
                  f"refusing to start. Investigate before moving it aside.", file=sys.stderr)
            return 2
    service = config.build_service()
    print(f"x402gate signer {service.address} listening on {config.path('socket')}", flush=True)
    serve(service, config.path("socket"), config.reconcile_interval_seconds,
          config.socket_mode)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    import httpx
    config = Config.load(args.config)
    transport = httpx.HTTPTransport(uds=str(config.path("socket")))
    with httpx.Client(transport=transport, base_url="http://x402gate", timeout=10) as client:
        response = client.get("/v1/status")
        response.raise_for_status()
        status = response.json()
    print(json.dumps(status, indent=2))
    return 1 if status.get("degraded") else 0


def cmd_verify_audit(args: argparse.Namespace) -> int:
    from .audit import Audit
    path = Path(args.audit) if args.audit else Config.load(args.config).path("audit")
    audit = Audit(path=path, strict=False)
    try:
        ok, problem = audit.verify()
        count = len(audit.entries())
    finally:
        audit.close()
    if ok:
        print(f"audit chain intact: {count} record(s) in {path}")
        print("note: records removed from the END of the file cannot be detected locally.")
        return 0
    print(f"AUDIT CHAIN BROKEN in {path}: {problem}", file=sys.stderr)
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="x402gate",
                                     description="x402 spending gate and signer service")
    sub = parser.add_subparsers(dest="command", required=True)

    new_key = sub.add_parser("new-key", help="create a fresh wallet key file (mode 600)")
    new_key.add_argument("--out", required=True)
    new_key.set_defaults(func=cmd_new_key)

    for name, func, help_text in (
            ("check-config", cmd_check_config, "validate a config file"),
            ("serve", cmd_serve, "run the signer service"),
            ("status", cmd_status, "show a running service's status")):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--config", required=True)
        p.set_defaults(func=func)

    verify = sub.add_parser("verify-audit", help="check the audit log's hash chain")
    source = verify.add_mutually_exclusive_group(required=True)
    source.add_argument("--config")
    source.add_argument("--audit")
    verify.set_defaults(func=cmd_verify_audit)
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
