from fastapi import Header, HTTPException
from .config import cfg

async def verify_api_key(x_rapidapi_key: str = Header(None)):
    """
    Enforce API key auth. RapidAPI will inject X-RapidAPI-Key automatically
    for subscribed users. Locally you can use EXPECTED_API_KEY.
    """
    if not x_rapidapi_key:
        raise HTTPException(status_code=401, detail="Missing X-RapidAPI-Key header")
    if x_rapidapi_key != cfg.EXPECTED_API_KEY:
        # In production, you might trust RapidAPI validation only
        # But we check against EXPECTED_API_KEY for dev
        raise HTTPException(status_code=403, detail="Invalid API Key")
