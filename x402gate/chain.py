"""ChainVerifier: reads EIP-3009 authorization state on-chain to resolve held reservations."""

from __future__ import annotations

import logging
from typing import Any, Callable
from urllib.parse import urlparse

_log = logging.getLogger("x402gate.chain")

_LOOPBACK = {"localhost", "127.0.0.1", "::1"}
RELEASE_BLOCKS = ("finalized", "safe")

_AUTHORIZATION_STATE_ABI = [{
    "name": "authorizationState",
    "type": "function",
    "stateMutability": "view",
    "inputs": [{"name": "authorizer", "type": "address"},
               {"name": "nonce", "type": "bytes32"}],
    "outputs": [{"name": "", "type": "bool"}],
}]


def check_rpc_url(url: str) -> None:
    """HTTPS only, except loopback: a plaintext RPC could be told to report a used nonce as unused."""
    parsed = urlparse(url)
    if parsed.scheme == "https" and parsed.hostname:
        return
    if parsed.scheme == "http" and parsed.hostname in _LOOPBACK:
        return
    raise ValueError(f"RPC URL {url!r} must use https (plain http is allowed only on loopback)")


class ChainVerifier:

    def __init__(self, rpc_urls: dict[str, str | list[str]], timeout_seconds: float = 10.0,
                 web3_factory: Callable[[str, float], Any] | None = None,
                 release_block: str = "finalized") -> None:
        """Several URLs per network must agree; any disagreement or failure is "unknown".

        release_block is the head a release is judged at; "safe" frees budget sooner but a
        deeper reorg can still land an authorization released there.
        """
        if not rpc_urls:
            raise ValueError("ChainVerifier needs at least one network RPC URL")
        if release_block not in RELEASE_BLOCKS:
            raise ValueError(f"release_block must be one of {RELEASE_BLOCKS}, not {release_block!r}")
        self._release_block = release_block
        self._rpc_urls: dict[str, list[str]] = {}
        for network, urls in rpc_urls.items():
            urls = [urls] if isinstance(urls, str) else list(urls)
            if not urls:
                raise ValueError(f"no RPC URL for {network}")
            for url in urls:
                check_rpc_url(url)
            self._rpc_urls[network] = urls
        self._timeout = timeout_seconds
        self._factory = web3_factory or self._default_factory
        self._clients: dict[str, Any] = {}

    @staticmethod
    def _default_factory(url: str, timeout: float) -> Any:
        from web3 import Web3
        return Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": timeout}))

    def networks(self) -> tuple[str, ...]:
        return tuple(self._rpc_urls)

    @property
    def release_block(self) -> str:
        return self._release_block

    def authorization_used(self, network: str, asset: str, authorizer: str,
                           nonce: str | None, block: str = "latest") -> bool | None:
        """True used, False unused, None unknown; callers must treat None as "keep counting"."""
        urls = self._rpc_urls.get(network)
        if not urls or not nonce:
            return None
        answers = {self._authorization_used(network, url, asset, authorizer, nonce, block)
                   for url in urls}
        if len(answers) != 1:
            _log.error("RPCs for %s disagree on authorization state: %s", network, answers)
            return None
        return answers.pop()

    def _authorization_used(self, network: str, url: str, asset: str, authorizer: str,
                            nonce: str, block: str) -> bool | None:
        try:
            w3 = self._client(url)
            if not self._chain_matches(network, w3):
                return None
            from web3 import Web3
            contract = w3.eth.contract(address=Web3.to_checksum_address(asset),
                                       abi=_AUTHORIZATION_STATE_ABI)
            nonce_bytes = bytes.fromhex(nonce[2:] if nonce.startswith("0x") else nonce)
            if len(nonce_bytes) != 32:
                return None
            used = contract.functions.authorizationState(
                Web3.to_checksum_address(authorizer), nonce_bytes).call(block_identifier=block)
            # Only a real boolean is an answer; bool(None) would read as "unused" and free budget.
            return used if isinstance(used, bool) else None
        except Exception as exc:  # noqa: BLE001
            _log.warning("authorization check failed on %s: %s", network, exc)
            return None

    def block_time(self, network: str, block: str = "latest") -> int | None:
        """The earliest time of that head across RPCs, or None if any can't answer."""
        urls = self._rpc_urls.get(network)
        if not urls:
            return None
        times = []
        for url in urls:
            try:
                w3 = self._client(url)
                if not self._chain_matches(network, w3):
                    return None
                times.append(int(w3.eth.get_block(block)["timestamp"]))
            except Exception as exc:  # noqa: BLE001
                _log.warning("block time read failed on %s: %s", network, exc)
                return None
        return min(times)

    def outcome(self, network: str, asset: str, authorizer: str, nonce: str | None,
                valid_before: int | None) -> bool | None:
        """True if used at the latest head. False only if unused at the release head and that
        head's time is past valid_before: a reorg above it could still land the authorization."""
        used = self.authorization_used(network, asset, authorizer, nonce)
        if used is True:
            return True
        if used is not False or valid_before is None:
            return None
        settled_time = self.block_time(network, self._release_block)
        if settled_time is None or settled_time <= valid_before:
            return None
        if self.authorization_used(network, asset, authorizer, nonce,
                                   self._release_block) is False:
            return False
        return None

    def _client(self, url: str) -> Any:
        if url not in self._clients:
            self._clients[url] = self._factory(url, self._timeout)
        return self._clients[url]

    @staticmethod
    def _chain_matches(network: str, w3: Any) -> bool:
        # Checked on every call: an endpoint can be repointed after the first answer.
        try:
            expected = int(network.split(":", 1)[1])
        except (IndexError, ValueError):
            return False
        actual = int(w3.eth.chain_id)
        if actual != expected:
            _log.error("RPC for %s reports chain id %s; refusing to use it", network, actual)
        return actual == expected


def reconcile_held(state: Any, audit: Any, verifier: Any, authorizer: str | None, *,
                   count_unverifiable: bool,
                   record: Callable[[Callable[[], Any]], None]) -> dict[str, int]:
    """Resolve expired held reservations from the chain; ledger first, then audit via `record`.

    count_unverifiable=True commits entries that can't be checked at all (fail closed).
    """
    counts = {"committed": 0, "released": 0, "unknown": 0, "unverified": 0}
    for entry in state.awaiting_verification():
        rid, ref = entry["id"], entry.get("ref")
        verifiable = (verifier is not None and bool(authorizer) and isinstance(ref, str)
                      and not ref.startswith("id:"))
        verdict = (verifier.outcome(entry.get("network", ""), entry.get("asset", ""),
                                    authorizer, ref, entry.get("valid_before"))
                   if verifiable else None)
        if verdict is True:
            state.commit(rid)
            record(lambda: audit.record_settlement(
                rid, True, settled_amount_atomic=entry["amount"],
                error="confirmed on-chain: authorization nonce was used"))
            counts["committed"] += 1
        elif verdict is False:
            state.release(rid)
            record(lambda: audit.record_release(
                rid, "authorization expired unused (confirmed on-chain)"))
            counts["released"] += 1
        elif not verifiable and count_unverifiable:
            state.commit(rid)
            record(lambda: audit.record_settlement(
                rid, False, settled_amount_atomic=entry["amount"],
                error="UNVERIFIED: the outcome could not be checked on-chain, so this "
                      "authorization is counted as spent (fail closed)"))
            counts["unverified"] += 1
        else:
            counts["unknown"] += 1
    return counts
