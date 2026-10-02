"""RemoteSigner: a keyless ClientEvmSigner that asks the x402gate signer service to sign."""

from __future__ import annotations

from contextvars import ContextVar
from typing import Any

import httpx

# Set per payment by Firewall.before_payment_creation.
PAYMENT_METADATA: ContextVar[dict[str, Any] | None] = ContextVar(
    "x402gate_payment_metadata", default=None
)


class RemoteSigner:

    def __init__(self, socket_path: str | None = None, *, base_url: str | None = None,
                 timeout_seconds: float = 10.0, transport: httpx.BaseTransport | None = None,
                 caller: str | None = None) -> None:
        """base_url is for tests: never expose the signer on a network port, anyone who can reach it can ask."""
        if transport is None:
            if socket_path is None and base_url is None:
                raise ValueError("RemoteSigner needs a socket_path or a base_url")
            transport = httpx.HTTPTransport(uds=socket_path) if socket_path else None
        self._client = httpx.Client(transport=transport, base_url=base_url or "http://x402gate",
                                    timeout=timeout_seconds)
        self._caller = caller
        response = self._client.get("/v1/address")
        response.raise_for_status()
        self._address = response.json()["address"]

    @property
    def address(self) -> str:
        return self._address

    def sign_typed_data(self, domain: Any, types: Any, primary_type: str,
                        message: dict[str, Any]) -> bytes:
        """Raises PermissionError when the service refuses."""
        metadata = dict(PAYMENT_METADATA.get() or {})
        if self._caller and "caller" not in metadata:
            metadata["caller"] = self._caller
        body = {
            "domain": self._domain(domain),
            "types": {name: [self._field(f) for f in fields] for name, fields in types.items()},
            "primaryType": primary_type,
            "message": {key: self._value(value) for key, value in message.items()},
            "metadata": metadata,
        }
        response = self._client.post("/v1/sign", json=body)
        if response.status_code == 403:
            refusal = response.json()
            raise PermissionError(
                f"x402gate signer refused: {refusal.get('rule')}: {refusal.get('reason')}")
        response.raise_for_status()
        signature = response.json()["signature"]
        return bytes.fromhex(signature[2:] if signature.startswith("0x") else signature)

    def status(self) -> dict[str, Any]:
        response = self._client.get("/v1/status")
        response.raise_for_status()
        return response.json()

    def close(self) -> None:
        self._client.close()

    @staticmethod
    def _domain(domain: Any) -> dict[str, Any]:
        if isinstance(domain, dict):
            return dict(domain)
        return {"name": domain.name, "version": domain.version,
                "chainId": domain.chain_id, "verifyingContract": domain.verifying_contract}

    @staticmethod
    def _field(field: Any) -> dict[str, str]:
        if isinstance(field, dict):
            return {"name": field["name"], "type": field["type"]}
        return {"name": field.name, "type": field.type}

    @staticmethod
    def _value(value: Any) -> Any:
        if isinstance(value, (bytes, bytearray)):
            return "0x" + bytes(value).hex()
        return value
