from dotenv import load_dotenv
import os

load_dotenv()

class Config:
    PORT = int(os.getenv("PORT", "8080"))
    DEFAULT_STRATEGY = os.getenv("DEFAULT_STRATEGY", "redact")  # redact | partial | tokenize
    SECRET = os.getenv("SECRET", "replace-me-with-secure-key")
    DROP_FIELDS = [s.strip() for s in os.getenv("DROP_FIELDS", "password,otp").split(",") if s.strip()]
    EXPECTED_API_KEY = os.getenv("EXPECTED_API_KEY", "test-key")  # used for local/test

cfg = Config()
