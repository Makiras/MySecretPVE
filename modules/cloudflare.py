import requests
from typing import List
from ipaddress import IPv4Network, IPv6Network, ip_network


class Cloudflare:

    def __init__(self, api_token: str = ""):
        self.api_token = api_token

    def get_cdn_iprange(self, isv6: bool = True) :
        if isv6:
            url = "https://www.cloudflare.com/ips-v6"
        else:
            url = "https://www.cloudflare.com/ips-v4"
        r = requests.get(url)
        if r.status_code != 200:
            raise Exception('Failed to get Cloudflare IPv6 address')
        ip_range_str = r.text.splitlines()
        ipNetworks = []  # type: List[IPv6Network|IPv4Network]
        for ip_range in ip_range_str:
            ipNetworks.append(ip_network(ip_range))
        return ipNetworks
    