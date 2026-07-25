from pydantic import BaseModel
from typing import Optional, Any
from datetime import datetime, timezone


class MacroStep(BaseModel):
    url: str
    method: str = "GET"
    headers: dict = {}
    body: str | None = None
    extract: dict[str, str] = {}
    fail_on: list[dict] = []


class AuthProfile(BaseModel):
    id: str = ""
    name: str
    target_url: str = ""
    login_url: str = ""
    login_method: str = "POST"
    login_credentials: dict[str, str] = {}
    login_headers: dict[str, str] = {}
    login_body: str = ""
    csrf_token_extract: str = ""
    session_indicator: str = ""
    session_indicator_type: str = "cookie"
    check_url: str = ""
    macro_steps: list[MacroStep] = []
    created_at: str = ""
    updated_at: str = ""

    @property
    def is_valid(self) -> bool:
        return bool(self.login_url or self.macro_steps)

    def to_macro_config(self) -> list[dict]:
        if self.macro_steps:
            return [s.model_dump() for s in self.macro_steps]
        step = {
            "url": self.login_url,
            "method": self.login_method,
            "headers": dict(self.login_headers),
            "body": self.login_body,
            "extract": {},
            "fail_on": [],
        }
        if self.csrf_token_extract:
            step["extract"]["csrf_token"] = self.csrf_token_extract
        return [step]
