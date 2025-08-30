from app.masking.strategies import mask_any
from app.config import cfg

def test_email_mask_redact():
    payload = {"email": "john.doe@example.com", "notes": "contact me at john.doe@example.com"}
    masked = mask_any(payload, "redact", cfg.SECRET, cfg.DROP_FIELDS)
    assert masked["email"] == "[EMAIL]"
    assert "[EMAIL]" in masked["notes"]

def test_partial_phone_mask():
    payload = {"mobile": "0721234567"}
    masked = mask_any(payload, "partial", cfg.SECRET, cfg.DROP_FIELDS)
    assert masked["mobile"].startswith("072") and masked["mobile"].endswith("67")

def test_sa_id_tokenize_if_valid():
    valid_id = "9002205800085"  # example pattern used earlier
    payload = {"idNumber": valid_id}
    masked = mask_any(payload, "tokenize", cfg.SECRET, cfg.DROP_FIELDS)
    assert masked["idNumber"].startswith("pii_")