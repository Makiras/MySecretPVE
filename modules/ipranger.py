import requests
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network


class IPRanger:

    def __init__(self,
                 interface4: str = '',
                 interface6: str = '',
                 ip6prefix_len: int = 60):
        self.interface4 = interface4
        self.interface6 = interface6

        self.ip: IPv4Address
        self.ip4_net: IPv4Network
        self.ip6: IPv6Address
        self.ip6_net: IPv6Network

        self.get_ip()
        self.get_ip6(ip6prefix_len)

    def get_ip(self):
        if self.interface4:
            # Using system netifaces
            pass
        else:
            # Using Web API https://4.ipw.cn
            r = requests.get('https://4.ipw.cn')
            if r.status_code != 200:
                raise Exception('Failed to get IPv4 address')
            self.ip = ip_address(r.text)  # type: ignore
            self.ip4_net = ip_network(f'{self.ip}/32',
                                      strict=False)  # type: ignore

    def get_ip6(self, ip6prefix_len):
        if self.interface6:
            # Using system netifaces
            pass
        else:
            # Using Web API https://6.ipw.cn
            r = requests.get('https://6.ipw.cn')
            if r.status_code != 200:
                raise Exception('Failed to get IPv6 address')
            self.ip6 = ip_address(r.text)  # type: ignore
            self.ip6_net = ip_network(f'{self.ip6}/{ip6prefix_len}',
                                      strict=False)  # type: ignore

    def __str__(self) -> str:
        return f'IPv4: {self.ip}\nIPv4 Network: {self.ip4_net}\nIPv6: {self.ip6}\nIPv6 Network: {self.ip6_net}\n'


if __name__ == '__main__':
    ipr = IPRanger()
    print(ipr)