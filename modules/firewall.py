from proxmoxer import ProxmoxAPI, ProxmoxResource
from typing import List, Dict, Any
from ipaddress import IPv4Network, IPv6Network, ip_network


class Firewall:

    def __init__(self, proxmox: ProxmoxAPI):
        self.proxmox: ProxmoxAPI = proxmox
        self.firewall: ProxmoxResource = self.proxmox.cluster.firewall  # type: ignore

    def get_aliases(self) -> List[Dict[str, str]]:
        return self.firewall.aliases.get()  # type: ignore

    def check_alias(self, alias: str) -> str:
        res = self.firewall.aliases(alias).get()
        return res["cidr"] if res else ''

    def create_alias(self, alias: str, ip: Any) -> None:
        self.firewall.aliases.post(alias=alias, cidr=str(ip))

    def delete_alias(self, alias: str) -> None:
        self.firewall.aliases(alias).delete()
    
    def update_alias(self, alias: str, ip: Any) -> None:
        self.firewall.aliases(alias).put(cidr=str(ip))

    def get_ipsets(self) -> List[Dict[str, str]]:
        return self.firewall.ipset.get()  # type: ignore

    def check_ipset(self, ipset: str) -> List[str]:
        res = self.firewall.ipset(ipset).get()
        return [i["cidr"] for i in res] if res else []

    def create_ipset(self, ipset: str, ip_list: List[str] = []) -> None:
        self.firewall.ipset.post(ipset=ipset)
        for ip in ip_list:
            self.firewall.ipset(ipset).post(cidr=str(ip))

    def delete_ipset(self, ipset: str) -> None:
        self.firewall.ipset(ipset).delete()

    def update_ipset(self, ipset: str, ip_list: List[Any] = []) -> None:
        for ip in self.check_ipset(ipset):
            if ip_network(ip) not in ip_list:
                self.firewall.ipset(ipset).delete(ip=ip)
            else:
                ip_list.remove(ip_network(ip))
        for ip in ip_list:
            self.firewall.ipset(ipset).post(cidr=str(ip))
