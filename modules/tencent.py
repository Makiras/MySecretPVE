from typing import List
import json
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
                return [node.Ipv6 if isv6 else node.Ip for node in resp.Ips ] 
            return []
        except TencentCloudSDKException as err:
            print(err)
            raise err

    def ip_of_domain_list(self, domain_list: list, isv6: bool = True) -> List[str]:
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

        domains = [] # type: List[str]
        if resp.Domains:
            domains = [node.Domain for node in resp.Domains]
        
        ip_range_str = self.ip_of_domain_list(domains, isv6)
        ipNetworks = [] # type: List[IPv6Network|IPv4Network]
        for ip_range in ip_range_str:
            ipNetwork = ip_network(ip_range, strict=False)
            ipNetworks.append(ipNetwork)
        
        return ipNetworks



if __name__ == "__main__":
    print(Tencent("", "").get_cdn_iprange(isv6=True))
