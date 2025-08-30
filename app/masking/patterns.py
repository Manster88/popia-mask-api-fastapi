import re

patterns = {
    # Emails (case-insensitive)
    "email": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    # South African phone: +27 or 0 followed by 9 digits (allow spaces/dashes)
    "phone_za": re.compile(r"\b(?:\+?27|0)[\s-]?\d{2}[\s-]?\d{3}[\s-]?\d{4}\b"),
    # 13-digit sequences (candidate SA ID; validated separately)
    "id_za": re.compile(r"\b\d{13}\b"),
    # IPv4 addresses (basic)
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    # Simple address hint (street/road/ave/drive/...); crude but useful for redaction
    "address_hint": re.compile(r"\b\d{1,5}\s+[A-Za-z]+(?:\s+[A-Za-z]+)*\s+(?:Street|St|Road|Rd|Ave|Avenue|Drive|Dr|Close|Cl|Lane|Ln)\b", re.IGNORECASE),
    # Very broad plate pattern (can be refined by province rules)
    "plate_za": re.compile(r"\b[A-Z]{2,3}\s?\d{2,3}\s?[A-Z]{0,2}\b", re.IGNORECASE)
}
