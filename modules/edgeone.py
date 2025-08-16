from __future__ import annotations
import requests
from typing import List
from ipaddress import IPv4Network, IPv6Network, ip_network


class EdgeOne:

    def __init__(self, endpoint: str = "https://api.edgeone.ai/ips"):
        # Public endpoint that returns newline-separated CIDR ranges (IPv4 + IPv6)
        self.endpoint = endpoint

    def get_cdn_iprange(self, isv6: bool = True) -> List[IPv6Network | IPv4Network]:
        """Fetch EdgeOne back-to-origin IP ranges.

        The endpoint returns a mixed list of IPv4 and IPv6 CIDR blocks separated by newlines.
        This method filters by IP family and returns parsed ipaddress network objects.
        """
        r = requests.get(self.endpoint, timeout=15)
        if r.status_code != 200:
            raise Exception("Failed to get EdgeOne IP address ranges")
        lines = [ln.strip() for ln in r.text.splitlines() if ln.strip()]
        # Filter by IP family: IPv6 contains ':', IPv4 does not
        if isv6:
            lines = [ln for ln in lines if ":" in ln]
        else:
            lines = [ln for ln in lines if ":" not in ln]
        networks: list[IPv6Network | IPv4Network] = []
        for cidr in lines:
            try:
                networks.append(ip_network(cidr))
            except Exception:
                # Skip malformed lines defensively
                continue
        return networks


if __name__ == "__main__":
    eo = EdgeOne()
    print("IPv4 ranges:", len(eo.get_cdn_iprange(isv6=False)))
    print("IPv6 ranges:", len(eo.get_cdn_iprange(isv6=True)))
