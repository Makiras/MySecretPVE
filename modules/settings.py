from dataclasses import dataclass, field
from typing import Dict, Any

from config import (
    PVE_HOST,
    PVE_USER,
    PVE_PASSWORD,
    PVE_SSL_VERIFY,
    TENCENT_SECRET,
    TENCENT_KEY,
)


@dataclass
class Settings:
    """Runtime configuration that can be updated via the web UI."""

    pve: Dict[str, Any] = field(default_factory=lambda: {
        "host": PVE_HOST,
        "user": PVE_USER,
        "password": PVE_PASSWORD,
        "ssl_verify": PVE_SSL_VERIFY,
    })
    tencent: Dict[str, Any] = field(default_factory=lambda: {
        "secret": TENCENT_SECRET,
        "key": TENCENT_KEY,
    })

    def update_pve(self, host: str, user: str, password: str, ssl_verify: bool) -> None:
        self.pve.update({
            "host": host,
            "user": user,
            "password": password,
            "ssl_verify": ssl_verify,
        })

    def update_tencent(self, secret: str, key: str) -> None:
        self.tencent.update({"secret": secret, "key": key})
