from functools import lru_cache
from pydantic import BaseSettings


class Settings(BaseSettings):
    oidc: str = "https://localhost:5000/vc/connect/authorize/"
    scope: str = "openid profile verified-email"
    code: str = "sadasdsdasd"
    nonce: str = "sdasdasd"

    class Config:
        env_prefix = "APP_"

@lru_cache()
def get_setting():
    return Settings()