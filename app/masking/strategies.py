import hmac
import hashlib
from .patterns import patterns
from .validators import is_valid_south_african_id
from typing import Any, List

def redact_label(label: str) -> str:
    return f"[{label}]"

def partial_mask(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    # preserve beginning 3 and last 2
    return value[:3] + "*" * max(0, len(value) - 5) + value[-2:]

def tokenize_value(value: str, secret: str) -> str:
    # HMAC-SHA256 and hex -> short token
    hm = hmac.new(secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()
    return "pii_" + hm[:32]

def replace_by_strategy(value: str, label: str, strategy: str, secret: str) -> str:
    if strategy == "redact":
        return redact_label(label)
    if strategy == "partial":
        return partial_mask(value)
    return tokenize_value(value, secret)

def mask_string(s: str, strategy: str, secret: str) -> str:
    # order: email, phone, id (with validation), ipv4, plate, address hints
    s = patterns["email"].sub(lambda m: replace_by_strategy(m.group(0), "EMAIL", strategy, secret), s)
    s = patterns["phone_za"].sub(lambda m: replace_by_strategy(m.group(0), "PHONE", strategy, secret), s)
    # For SA ID ensure validation before masking
    def id_repl(m):
        candidate = m.group(0)
        return replace_by_strategy(candidate, "SA_ID", strategy, secret) if is_valid_south_african_id(candidate) else candidate
    s = patterns["id_za"].sub(id_repl, s)
    s = patterns["ipv4"].sub(lambda m: replace_by_strategy(m.group(0), "IP", strategy, secret), s)
    s = patterns["plate_za"].sub(lambda m: replace_by_strategy(m.group(0), "PLATE", strategy, secret), s)
    s = patterns["address_hint"].sub(lambda m: replace_by_strategy(m.group(0), "ADDRESS", strategy, secret), s)
    return s

def mask_any(value: Any, strategy: str, secret: str, drop_fields: List[str]) -> Any:
    if value is None:
        return value
    if isinstance(value, str):
        return mask_string(value, strategy, secret)
    if isinstance(value, bool) or isinstance(value, (int, float)):
        # convert numeric-looking values to string scanning (e.g. numeric ID)
        if isinstance(value, (int, float)):
            return mask_string(str(value), strategy, secret)
        return value
    if isinstance(value, list):
        return [mask_any(v, strategy, secret, drop_fields) for v in value]
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if k in drop_fields:
                # drop sensitive fields completely
                continue
            kl = k.lower()
            label = None
            if "email" in kl:
                label = "EMAIL"
            elif any(x in kl for x in ("phone", "mobile")):
                label = "PHONE"
            elif "id" in kl and isinstance(v, (str, int)):
                label = "SA_ID"
            elif "passport" in kl:
                label = "PASSPORT"
            elif "name" in kl:
                label = "NAME"
            elif "address" in kl:
                label = "ADDRESS"

            if label and isinstance(v, (str, int)):
                out[k] = replace_by_strategy(str(v), label, strategy, secret)
            else:
                out[k] = mask_any(v, strategy, secret, drop_fields)
        return out
    return value
