"""PaymentIntent: the payment the firewall judges, parsed from x402 objects or EIP-712 requests."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable


class IntentParseError(ValueError):
    """Malformed payment input; callers must treat it as a denial."""


@dataclass(frozen=True)
class PaymentIntent:
    recipient: str
    amount_atomic: int
    asset: str
    network: str
    scheme: str
    resource: str | None
    caller: str
    raw: dict[str, Any]
    # 0 means the server stated no window; the window rule denies it.
    max_timeout_seconds: int = 0
    created_at: float = field(default_factory=time.time)


def from_context(context: Any, caller: str = "agent",
                 clock: Callable[[], float] | None = None) -> PaymentIntent:
    req = getattr(context, "selected_requirements", None)
    if req is None:
        raise IntentParseError("context has no selected_requirements")

    raw_amount = getattr(req, "amount", None)
    # Canonical digits only: int() also accepts "1_000", "+5", whitespace and non-Latin digits.
    canonical = (isinstance(raw_amount, str) and raw_amount.isascii() and raw_amount.isdigit()) \
        or (isinstance(raw_amount, int) and not isinstance(raw_amount, bool))
    if not canonical:
        raise IntentParseError(f"amount is not an integer atomic value: {raw_amount!r}")
    amount_atomic = int(raw_amount)
    if amount_atomic < 0:
        raise IntentParseError(f"amount is negative: {amount_atomic}")

    recipient = getattr(req, "pay_to", None)
    if not recipient:
        raise IntentParseError("requirements missing pay_to")

    # Key on the url only: the ResourceInfo repr changes with unrelated fields.
    resource = None
    pr = getattr(context, "payment_required", None)
    if pr is not None:
        res = getattr(pr, "resource", None)
        if res is not None:
            url = getattr(res, "url", None)
            resource = str(url) if url else (res if isinstance(res, str) else None)

    try:
        max_timeout_seconds = int(getattr(req, "max_timeout_seconds", 0) or 0)
    except (TypeError, ValueError):
        max_timeout_seconds = 0
    if max_timeout_seconds < 0:
        max_timeout_seconds = 0

    return PaymentIntent(
        recipient=recipient,
        amount_atomic=amount_atomic,
        asset=getattr(req, "asset", "") or "",
        network=getattr(req, "network", "") or "",
        scheme=getattr(req, "scheme", "") or "",
        resource=resource,
        caller=caller,
        raw=req.model_dump() if hasattr(req, "model_dump") else dict(getattr(req, "__dict__", {})),
        max_timeout_seconds=max_timeout_seconds,
        created_at=(clock or time.time)(),
    )


TRANSFER_WITH_AUTHORIZATION = "TransferWithAuthorization"
TRANSFER_WITH_AUTHORIZATION_FIELDS = (
    ("from", "address"), ("to", "address"), ("value", "uint256"),
    ("validAfter", "uint256"), ("validBefore", "uint256"), ("nonce", "bytes32"),
)
_UINT256_MAX = 2**256 - 1
_MAX_RESOURCE_CHARS = 2048
_MAX_CALLER_CHARS = 128


def _address(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or len(value) != 42 or not value.startswith("0x"):
        raise IntentParseError(f"{field_name} is not a 20-byte hex address: {value!r}")
    try:
        int(value[2:], 16)
    except ValueError:
        raise IntentParseError(f"{field_name} is not hex: {value!r}")
    return value


def _uint(value: Any, field_name: str) -> int:
    # bool is an int subclass; True must not become an amount of 1.
    if isinstance(value, bool):
        raise IntentParseError(f"{field_name} is not an integer: {value!r}")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and value.isascii() and value.isdigit():
        # ASCII only: isdigit() also accepts "²" and non-Latin digits.
        number = int(value)
    else:
        raise IntentParseError(f"{field_name} is not a non-negative integer: {value!r}")
    if not 0 <= number <= _UINT256_MAX:
        raise IntentParseError(f"{field_name} is outside uint256: {value!r}")
    return number


def _nonce(value: Any) -> str:
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    elif isinstance(value, str) and value.startswith("0x"):
        try:
            raw = bytes.fromhex(value[2:])
        except ValueError:
            raise IntentParseError(f"nonce is not hex: {value!r}")
    else:
        raise IntentParseError(f"nonce must be 32 bytes or 0x-hex: {value!r}")
    if len(raw) != 32:
        raise IntentParseError(f"nonce must be exactly 32 bytes, got {len(raw)}")
    return "0x" + raw.hex()


def _type_fields(fields: Any) -> tuple[tuple[str, str], ...]:
    normalised = []
    for item in fields or ():
        if isinstance(item, dict):
            normalised.append((item.get("name"), item.get("type")))
        else:
            normalised.append((getattr(item, "name", None), getattr(item, "type", None)))
    return tuple(normalised)


def from_typed_data(domain: Any, types: Any, primary_type: str, message: Any, *,
                    signer_address: str, metadata: dict[str, Any] | None = None,
                    clock: Callable[[], float] | None = None) -> PaymentIntent:
    """Parse a canonical EIP-3009 TransferWithAuthorization request; raise on anything else.

    The normalised copy in raw["signable"] is what must be signed, never the request as sent.
    """
    metadata = metadata or {}
    now = (clock or time.time)()

    if primary_type != TRANSFER_WITH_AUTHORIZATION:
        raise IntentParseError(f"refusing to sign primary type {primary_type!r}; "
                               f"only {TRANSFER_WITH_AUTHORIZATION} is supported")
    if not isinstance(types, dict):
        raise IntentParseError("types must be a mapping")
    unexpected = set(types) - {TRANSFER_WITH_AUTHORIZATION, "EIP712Domain"}
    if unexpected:
        raise IntentParseError(f"unexpected type definitions: {sorted(unexpected)}")
    if _type_fields(types.get(TRANSFER_WITH_AUTHORIZATION)) != TRANSFER_WITH_AUTHORIZATION_FIELDS:
        raise IntentParseError("TransferWithAuthorization schema differs from EIP-3009")

    get = (domain.get if isinstance(domain, dict)
           else lambda key: getattr(domain, {"chainId": "chain_id",
                                             "verifyingContract": "verifying_contract"}
                                    .get(key, key), None))
    name, version = get("name"), get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        raise IntentParseError("domain name and version must be strings")
    chain_id = _uint(get("chainId"), "chainId")
    asset = _address(get("verifyingContract"), "verifyingContract")

    if not isinstance(message, dict):
        raise IntentParseError("message must be a mapping")
    extra_keys = set(message) - {name for name, _ in TRANSFER_WITH_AUTHORIZATION_FIELDS}
    if extra_keys:
        raise IntentParseError(f"unexpected message fields: {sorted(extra_keys)}")
    payer = _address(message.get("from"), "from")
    recipient = _address(message.get("to"), "to")
    value = _uint(message.get("value"), "value")
    valid_after = _uint(message.get("validAfter"), "validAfter")
    valid_before = _uint(message.get("validBefore"), "validBefore")
    nonce = _nonce(message.get("nonce"))

    if payer.lower() != signer_address.lower():
        raise IntentParseError(f"from {payer} is not this signer ({signer_address})")
    if valid_before <= now:
        raise IntentParseError("authorization is already expired (validBefore <= now)")
    if valid_after >= valid_before:
        raise IntentParseError("validAfter is not before validBefore")

    signable = {
        "domain": {"name": name, "version": version, "chainId": chain_id,
                   "verifyingContract": asset},
        "message": {"from": payer, "to": recipient, "value": value,
                    "validAfter": valid_after, "validBefore": valid_before,
                    "nonce": nonce},
    }
    # Metadata is agent-supplied: advisory only, and bounded before it reaches the audit.
    resource = metadata.get("resource")
    caller = metadata.get("caller")
    resource = resource[:_MAX_RESOURCE_CHARS] if isinstance(resource, str) else None
    caller = caller[:_MAX_CALLER_CHARS] if isinstance(caller, str) else None
    metadata = {k: v for k, v in (("resource", resource), ("caller", caller)) if v}
    return PaymentIntent(
        recipient=recipient,
        amount_atomic=value,
        asset=asset,
        network=f"eip155:{chain_id}",
        scheme="exact",
        resource=resource if isinstance(resource, str) and resource else None,
        caller=caller if isinstance(caller, str) and caller else "agent",
        raw={"signable": signable, "metadata_untrusted": dict(metadata)},
        max_timeout_seconds=int(valid_before - now),
        created_at=now,
    )
