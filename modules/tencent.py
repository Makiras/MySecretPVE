from typing import List
import json
import dns.resolver as dns
from tencentcloud.common import credential
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.cdn.v20180606 import cdn_client, models
from ipaddress import IPv4Network, IPv6Network, ip_network


class Tencent:

    def __init__(self, secretId: str, secretKey: str):
        try:
            cred = credential.Credential(secretId, secretKey)
            self.client = cdn_client.CdnClient(cred, "ap-guangzhou")
        except TencentCloudSDKException as err:
            print(err)

    # IPv6 list of domain
    def ip_of_domain(self, domain: str, isv6: bool = True) -> List[str]:
        try:
            req = models.DescribeIpStatusRequest()
            params = {
                "Domain": domain,
                "Layer": "last",
                "Segment": True,
                "ShowIpv6": True,
                "AbbreviationIpv6": True
            }
            req.from_json_string(json.dumps(params))
            resp = self.client.DescribeIpStatus(req)
            if resp.Ips:
                return [node.Ipv6 if isv6 else node.Ip for node in resp.Ips]
            return []
        except TencentCloudSDKException as err:
            print(err)
            raise err

    def ip_of_domain_list(self,
                          domain_list: list,
                          isv6: bool = True) -> List[str]:
        res_set: set = set()
        for domain in domain_list:
            if not isinstance(domain, str):
                raise TypeError("domain_list must be list of str")
            try:
                ip_list = self.ip_of_domain(domain, isv6)
                for ip in ip_list:
                    if ip is not None and ip != "-":
                        res_set.add(ip)
            except Exception as err:
                print(err)
                continue

        return list(res_set)

    def get_cdn_iprange(self, isv6: bool = True):
        req = models.DescribeDomainsRequest()
        req.from_json_string(json.dumps({}))
        resp = self.client.DescribeDomains(req)

        domains = []  # type: List[str]
        if resp.Domains:
            domains = [node.Domain for node in resp.Domains]

        ip_range_str = self.ip_of_domain_list(domains, isv6)
        ipNetworks = []  # type: List[IPv6Network|IPv4Network]
        for ip_range in ip_range_str:
            ipNetwork = ip_network(ip_range, strict=False)
            ipNetworks.append(ipNetwork)

        return ipNetworks


class TencentCDNDomain:

    def __init__(self, secretId: str, secretKey: str):
        try:
            cred = credential.Credential(secretId, secretKey)
            self.client = cdn_client.CdnClient(cred, "ap-guangzhou")
        except TencentCloudSDKException as err:
            print(err)

        self.resolver = dns.Resolver()
        self.resolver.nameservers = ["223.5.5.5", "1.1.1.1"]

    def check_domain(self,
                     domain: str,
                     dns_domain: str,
                     type: str = "AAAA") -> bool:
        # Get Now CDN IP
        try:
            req = models.DescribeDomainsRequest()
            params = {"Filters": [{"Name": "domain", "Value": [domain]}]}
            req.from_json_string(json.dumps(params))
            resp = self.client.DescribeDomains(req)
            if resp is None or resp.Domains is None or len(resp.Domains) == 0:
                raise Exception("Domain not found in CDN")
            origin_ip = resp.Domains[0].Origin.Origins[0]
        except TencentCloudSDKException as err:
            print(err)
            raise err
        # Get DNS IP
        try:
            resp = self.resolver.resolve(dns_domain, type)[0]
            if resp is None:
                raise Exception("DNS resolve failed")
            dns_ip = str(resp)
        except Exception as err:
            print(err)
            raise err
        # Update CDN IP
        print("Origin IP: {}, DNS IP: {}".format(origin_ip, dns_ip))
        if origin_ip == dns_ip:
            return True
        else:
            return self.update_domain_ip(domain, dns_ip,
                                         "ipv6" if type == "AAAA" else "ip")

    def update_domain_ip(self,
                         domain: str,
                         ip: str,
                         type: str = "ipv6") -> bool:
        print("Updating domain {} to {}".format(domain, ip))
        try:
            req = models.UpdateDomainConfigRequest()
            params = {
                "Domain": domain,
                "Origin": {
                    "Origins": [ip],
                    "ServerName": domain,
                    "OriginType": type
                }
            }
            req.from_json_string(json.dumps(params))
            resp = self.client.UpdateDomainConfig(req)
            return resp.RequestId is not None
        except TencentCloudSDKException as err:
            print(err)
            raise err


if __name__ == "__main__":
    import config as co
    print(
        Tencent(co.TENCENT_SECRET, co.TENCENT_KEY).get_cdn_iprange(isv6=True))
    TencentCDNDomain(co.TENCENT_SECRET, co.TENCENT_KEY).check_domain(
        "cdn_domain", "dns_domain", "AAAA")
