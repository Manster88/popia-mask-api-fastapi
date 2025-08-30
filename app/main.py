from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Any, Dict, List
import re
from datetime import datetime

app = FastAPI(
    title="POPIA Masking API",
    description="Mask, batch process, and validate sensitive data for POPIA compliance.",
    version="1.1.0"
)

# -------------------------------
# Utility masking functions
# -------------------------------

def mask_email(email: str, strategy: str = "partial") -> str:
    if strategy == "redact":
        return "[REDACTED]"
    elif strategy == "tokenize":
        return "EMAIL_TOKEN"
    elif strategy == "partial":
        parts = email.split("@")
        return parts[0][0] + "****@" + parts[1]
    return email

def mask_mobile(mobile: str, strategy: str = "partial") -> str:
    if strategy == "redact":
        return "[REDACTED]"
    elif strategy == "tokenize":
        return "MOBILE_TOKEN"
    elif strategy == "partial":
        return mobile[:3] + "*****" + mobile[-2:]
    return mobile

def mask_id_number(id_num: str, strategy: str = "partial") -> str:
    if strategy == "redact":
        return "[REDACTED]"
    elif strategy == "tokenize":
        return "ID_TOKEN"
    elif strategy == "partial":
        return id_num[:4] + "********" + id_num[-2:]
    return id_num

def apply_masking(payload: Dict[str, Any], strategy: str) -> Dict[str, Any]:
    masked = {}
    for key, value in payload.items():
        if not isinstance(value, str):
            masked[key] = value
            continue

        if re.match(r"[^@]+@[^@]+\.[^@]+", value):
            masked[key] = mask_email(value, strategy)
        elif re.match(r"^\d{10}$", value) or re.match(r"^0\d{9}$", value):
            masked[key] = mask_mobile(value, strategy)
        elif re.match(r"^\d{13}$", value):
            masked[key] = mask_id_number(value, strategy)
        else:
            masked[key] = value
    return masked

# -------------------------------
# SA ID validation
# -------------------------------

def validate_sa_id(id_number: str) -> Dict[str, Any]:
    if not re.match(r"^\d{13}$", id_number):
        return {"valid": False, "reason": "ID must be 13 digits"}

    # Extract birthdate (first 6 digits: YYMMDD)
    try:
        birthdate = datetime.strptime(id_number[:6], "%y%m%d")
    except ValueError:
        return {"valid": False, "reason": "Invalid birthdate"}

    # Luhn checksum validation
    def luhn_checksum(num: str) -> bool:
        digits = [int(d) for d in num]
        checksum = 0
        parity = len(digits) % 2
        for i, digit in enumerate(digits):
            if i % 2 == parity:
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit
        return checksum % 10 == 0

    if not luhn_checksum(id_number):
        return {"valid": False, "reason": "Checksum invalid"}

    return {"valid": True, "reason": "Checksum valid, birthdate valid"}

# -------------------------------
# Request Models
# -------------------------------

class MaskRequest(BaseModel):
    payload: Dict[str, Any]
    strategy: str = "partial"

class BatchMaskRequest(BaseModel):
    payloads: List[Dict[str, Any]]
    strategy: str = "partial"

class IdValidationRequest(BaseModel):
    idNumber: str

# -------------------------------
# Endpoints
# -------------------------------

@app.post("/mask")
def mask_data(request: MaskRequest):
    return {"masked": apply_masking(request.payload, request.strategy)}

@app.post("/mask/batch")
def mask_batch(request: BatchMaskRequest):
    masked_list = [apply_masking(record, request.strategy) for record in request.payloads]
    return {"masked": masked_list}

@app.post("/validate/id")
def validate_id(request: IdValidationRequest):
    result = validate_sa_id(request.idNumber)
    return {"idNumber": request.idNumber, **result}

@app.get("/health")
def health_check():
    return {"status": "ok", "service": "POPIA Masking API"}
