from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Any, Optional
from .masking.strategies import mask_any
from .config import cfg
from .dependencies import verify_api_key

router = APIRouter(
    prefix="/v1",
    tags=["masking"],
    dependencies=[Depends(verify_api_key)]  # enforce API key on all routes
)

class MaskRequest(BaseModel):
    payload: Any
    strategy: Optional[str] = None

@router.post("/mask", summary="Mask personal information in a JSON payload")
async def mask_endpoint(req: MaskRequest):
    """
    Accepts arbitrary JSON and applies POPIA-friendly data masking.

    - **redact** → replaces with `[EMAIL]`, `[PHONE]`, etc.
    - **partial** → keeps part of value visible (e.g., `072*****67`)
    - **tokenize** → replaces with irreversible token (HMAC-SHA256)

    Default strategy is configured in server (`DEFAULT_STRATEGY`).
    """
    strategy = req.strategy or cfg.DEFAULT_STRATEGY
    masked = mask_any(req.payload, strategy, cfg.SECRET, cfg.DROP_FIELDS)
    return {"masked": masked}
