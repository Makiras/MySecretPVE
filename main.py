from proxmoxer import ProxmoxAPI
from config import *
from modules.firewall import Firewall
from modules.tencent import Tencent
from modules.cloudflare import Cloudflare
from modules.ipranger import IPRanger
import ipaddress

proxmox = ProxmoxAPI(host=PVE_HOST, user=PVE_USER, password=PVE_PASSWORD, verify_ssl=PVE_SSL_VERIFY)
tencent = Tencent(secretId=TENCENT_SECRET, secretKey=TENCENT_KEY)
cloudflare = Cloudflare()
ipranger = IPRanger()

if __name__ == '__main__':
    firewall = Firewall(proxmox)

    # Update Tencent Cloud IP Set
    ip_list = tencent.get_cdn_iprange(isv6=True)
    firewall.update_ipset('tencent', ip_list)

    # Update Cloudflare IP Set
    ip_list = cloudflare.get_cdn_iprange(isv6=True)
    firewall.update_ipset('cloudflare', ip_list)

    # Update Home IP Alias
    firewall.update_alias('home', ipranger.ip6_net)

    