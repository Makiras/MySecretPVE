from __future__ import annotations
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
        # Proxmox API expects 'name' for alias identifier
        self.firewall.aliases.post(name=alias, cidr=str(ip))

    def delete_alias(self, alias: str) -> None:
        self.firewall.aliases(alias).delete()
    
    def update_alias(self, alias: str, ip: Any) -> None:
        self.firewall.aliases(alias).put(cidr=str(ip))

    def get_ipsets(self) -> List[Dict[str, str]]:
        return self.firewall.ipset.get()  # type: ignore

    def check_ipset(self, ipset: str) -> List[str]:
        res = self.firewall.ipset(ipset).get()
        return [i["cidr"] for i in res] if res else []

    def create_ipset(self, ipset: str, ip_list: List[str] | None = None, comment: str | None = None) -> None:
        """Create an IP set.

        Using a mutable list as a default argument can lead to subtle bugs
        because the list is shared across calls. Use ``None`` and initialize
        a new list on each invocation instead.
        """
        # Proxmox API expects 'name' for the ipset identifier
        if comment:
            self.firewall.ipset.post(name=ipset, comment=comment)
        else:
            self.firewall.ipset.post(name=ipset)
        if ip_list is None:
            ip_list = []
        for ip in ip_list:
            self.firewall.ipset(ipset).post(cidr=str(ip))

    def delete_ipset(self, ipset: str) -> None:
        self.firewall.ipset(ipset).delete()

    def update_ipset(self, ipset: str, ip_list: List[Any] | None = None) -> None:
        """Synchronize the IP set with the provided list.

        Avoids using a mutable default list which would retain values between
        calls and lead to incorrect firewall rules.
        """
        if ip_list is None:
            ip_list = []
        for ip in self.check_ipset(ipset):
            if ip_network(ip) not in ip_list:
                # Use path segment delete: /cluster/firewall/ipset/<name>/<cidr>
                self.firewall.ipset(ipset)(ip).delete()
            else:
                ip_list.remove(ip_network(ip))
        for ip in ip_list:
            self.firewall.ipset(ipset).post(cidr=str(ip))

    def add_ip_to_ipset(self, ipset: str, ip: Any) -> None:
        self.firewall.ipset(ipset).post(cidr=str(ip))

    def remove_ip_from_ipset(self, ipset: str, ip: Any) -> None:
        # Prefer path-segment deletion to avoid schema param issues
        self.firewall.ipset(ipset)(str(ip)).delete()

    def set_ipset_comment(self, ipset: str, comment: str | None) -> None:
        # Some PVE versions expect POST instead of PUT for updating ipset properties
        self.firewall.ipset.post(name=ipset, rename=ipset, comment=comment)

    def rename_ipset(self, ipset: str, new_name: str) -> None:
        """Rename an existing IPSet.

        Uses collection POST with name and rename fields for broad compatibility.
        """
        self.firewall.ipset.post(name=ipset, rename=new_name)
