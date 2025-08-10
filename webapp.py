from functools import wraps
import logging
import http.client as http_client
import sys
from ipaddress import ip_network

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
)
from proxmoxer import ProxmoxAPI

from config import (
    WEB_USERNAME,
    WEB_PASSWORD,
    FLASK_SECRET_KEY,
    ENABLE_HTTP_DEBUG,
    ENABLE_HTTP_DEBUG_SHOW_SECRETS,
)
from modules.firewall import Firewall
from modules.settings import Settings


app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

settings = Settings()

def setup_request_logging():
    """Enable verbose logging for proxmoxer and HTTP requests.

    Prints outbound request lines like:
    DEBUG:urllib3.connectionpool:Starting new HTTPS connection (1): host:8006
    DEBUG:urllib3.connectionpool:https://host:8006 "POST /api2/json/access/ticket HTTP/1.1" 200 None
    """
    # Ensure console handler exists and accepts DEBUG
    root = logging.getLogger()
    if not root.handlers:
        h = logging.StreamHandler(sys.stdout)
        h.setLevel(logging.DEBUG)
        h.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s'))
        root.addHandler(h)
    root.setLevel(logging.DEBUG)
    app.logger.setLevel(logging.DEBUG)

    # proxmoxer internal loggers (resource calls, https backend)
    for name in ("proxmoxer", "proxmoxer.core", "proxmoxer.backends.https"):
        logging.getLogger(name).setLevel(logging.INFO)

    # urllib3 connection logs outgoing requests lines
    logging.getLogger("urllib3").setLevel(logging.INFO)
    logging.getLogger("urllib3.connectionpool").setLevel(logging.DEBUG)

    # Optional: very verbose HTTP headers (stdout). Can be noisy.
    http_client.HTTPConnection.debuglevel = 0  # set to 1 for headers dump


def log_proxmox_init(where: str, host: str, port: int, verify_ssl: bool, user: str | None, token_name: str | None, using_token: bool, otp_value: str | None = None):
    safe_user = (user or '').split('@')[0]
    if otp_value and ENABLE_HTTP_DEBUG_SHOW_SECRETS:
        otp_info = otp_value
    else:
        otp_info = 'yes' if (otp_value not in (None, '')) else 'no'
    app.logger.info(
        f"[{where}] Proxmox init host={host} port={port} verify_ssl={verify_ssl} "
        f"user={safe_user or '-'} auth={'token' if using_token else 'password'} "
        f"token_name={'set' if token_name else 'none'} otp={otp_info}"
    )


# Enable logging if switch is on
if ENABLE_HTTP_DEBUG:
    setup_request_logging()


def _normalize_host_port_protocol(host: str, protocol: str | None, port: int | None):
    host = (host or "").strip()
    proto = (protocol or "https").lower().strip() if protocol else "https"
    p = port
    if host.startswith("http://"):
        proto = "http"; host = host[len("http://"):]
    elif host.startswith("https://"):
        proto = "https"; host = host[len("https://"):]
    # strip path/query/fragment (e.g., 192.168.52.64:8007/# or /pve?x=1)
    for sep in ["/", "?", "#"]:
        if sep in host:
            host = host.split(sep, 1)[0]
    host = host.rstrip("/")
    if host.startswith("[") and "]:" in host:
        addr, pp = host.rsplit(":", 1)
        host = addr
        if pp.isdigit():
            p = int(pp)
    elif ":" in host and host.count(":") == 1:
        addr, pp = host.split(":", 1)
        if pp.isdigit():
            host, p = addr, int(pp)
    if p is None:
        p = 8006
    return host, proto, p


def create_proxmox() -> ProxmoxAPI | None:
    pve_conf = settings.pve
    host, protocol, port = _normalize_host_port_protocol(
        pve_conf.get("host"), pve_conf.get("protocol"), pve_conf.get("port")
    )
    user = pve_conf.get("user")
    password = pve_conf.get("password")
    verify_ssl = bool(pve_conf.get("ssl_verify", True))
    token_name = (pve_conf.get("token_name") or "").strip()
    token_value = (pve_conf.get("token_value") or "").strip()
    if not host:
        return None
    # proxmoxer https 后端固定使用 HTTPS，协议配置仅用于归一化与未来扩展
    if token_value:
        log_proxmox_init("create_proxmox", host, port, verify_ssl, user, token_name, using_token=True, otp_value=None)
        return ProxmoxAPI(host=host, user=user, token_name=token_name, token_value=token_value, verify_ssl=verify_ssl, port=port, timeout=5)
    else:
        log_proxmox_init("create_proxmox", host, port, verify_ssl, user, token_name, using_token=False, otp_value=None)
        return ProxmoxAPI(host=host, user=user, password=password, verify_ssl=verify_ssl, port=port, timeout=5)

proxmox: ProxmoxAPI | None = None
firewall: Firewall | None = None


def get_firewall() -> Firewall | None:
    """Create Firewall instance on demand without doing it at app startup."""
    global proxmox, firewall
    if firewall is not None:
        return firewall
    proxmox = create_proxmox()
    if proxmox is None:
        return None
    firewall = Firewall(proxmox)
    return firewall


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username == WEB_USERNAME and password == WEB_PASSWORD:
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
        error = "Invalid username or password"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    # Avoid touching Proxmox on dashboard; only check settings.
    unconfigured = not bool((settings.pve.get("host") or "").strip())
    return render_template("dashboard.html", unconfigured=unconfigured)


@app.route("/whitelist", methods=["GET", "POST"])
@login_required
def whitelist():
    # 兼容旧链接：重定向到通用 IPSet 页面
    return redirect(url_for("ipsets_detail", name="whitelist"))


@app.route("/ipsets", methods=["GET", "POST"])
@login_required
def ipsets_index():
    message = None
    fw = get_firewall()
    if fw is None:
        return render_template("ipsets.html", ipsets=[], message="PVE 未配置，请先到设置页面配置。")
    if request.method == "POST":
        action = request.form.get("action")
        if action == "create":
            name = (request.form.get("name", "").strip())
            comment = (request.form.get("comment", "").strip())
            if not name:
                message = "名称不能为空"
            else:
                names = [i["name"] for i in fw.get_ipsets()]
                if name in names:
                    message = "该 IPSet 已存在"
                else:
                    fw.create_ipset(name, comment=comment or None)
                    message = "创建成功"
        elif action == "delete":
            name = (request.form.get("name", "").strip())
            if name:
                fw.delete_ipset(name)
                message = "已删除"
    ipsets = fw.get_ipsets()
    return render_template("ipsets.html", ipsets=ipsets, message=message)


@app.route("/ipsets/<name>", methods=["GET", "POST"])
@login_required
def ipsets_detail(name: str):
    message = None
    fw = get_firewall()
    if fw is None:
        return render_template("ipset_detail.html", name=name, comment='', ips=[], message="PVE 未配置，请先到设置页面配置。")
    if request.method == "POST":
        action = request.form.get("action")
        if action == "add":
            ip = request.form.get("ip", "")
            try:
                network = ip_network(ip, strict=False)
                fw.add_ip_to_ipset(name, network)
                message = "已添加"
            except ValueError:
                message = "无效的 IP/CIDR"
        elif action == "remove":
            ip = request.form.get("ip", "")
            if ip:
                fw.remove_ip_from_ipset(name, ip)
                message = "已移除"
        elif action == "delete_ipset":
            fw.delete_ipset(name)
            return redirect(url_for("ipsets_index"))
        elif action == "rename":
            new_name = (request.form.get("new_name", "").strip())
            if not new_name:
                message = "新名称不能为空"
            elif new_name == name:
                message = "新名称与原名称相同"
            else:
                fw.rename_ipset(name, new_name)
                return redirect(url_for("ipsets_detail", name=new_name))
        elif action == "update_comment":
            comment = (request.form.get("comment", "").strip())
            fw.set_ipset_comment(name, comment)
            message = "备注已更新"
        elif action == "bulk_import":
            mode = request.form.get("mode", "append")
            content = request.form.get("content", "")
            items = []
            for line in content.splitlines():
                for piece in line.replace(",", " ").split():
                    piece = piece.strip()
                    if not piece:
                        continue
                    try:
                        items.append(ip_network(piece, strict=False))
                    except ValueError:
                        pass
            if mode == "replace":
                fw.update_ipset(name, items)
                message = f"已替换 {len(items)} 条"
            else:
                # append only new ones
                existing = set(fw.check_ipset(name))
                added = 0
                for n in items:
                    if str(n) not in existing:
                        fw.add_ip_to_ipset(name, n)
                        added += 1
                message = f"已追加 {added} 条"
        elif action == "bulk_remove":
            q = (request.form.get("q", "").strip())
            if not q:
                message = "请先输入搜索条件再批量移除"
            else:
                ql = q.lower()
                current = fw.check_ipset(name)
                targets = [ip for ip in current if ql in ip.lower()]
                removed = 0
                for ip in targets:
                    try:
                        fw.remove_ip_from_ipset(name, ip)
                        removed += 1
                    except Exception:
                        pass
                message = f"已批量移除 {removed} 条"
    # filter/search
    q = (request.args.get("q", "").strip())
    ipsets = fw.get_ipsets()
    this = next((s for s in ipsets if s.get("name") == name), {})
    comment = this.get("comment", "") if isinstance(this, dict) else ""
    ips = fw.check_ipset(name)
    if q:
        ql = q.lower()
        ips = [i for i in ips if ql in i.lower()]
    return render_template("ipset_detail.html", name=name, comment=comment, ips=ips, message=message, q=q)


@app.route("/ipsets/<name>/export", methods=["GET"])
@login_required
def ipsets_export(name: str):
    fw = get_firewall()
    if fw is None:
        return ("PVE 未配置", 400, {"Content-Type": "text/plain; charset=utf-8"})
    ips = fw.check_ipset(name)
    body = "\n".join(ips) + ("\n" if ips else "")
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": f"attachment; filename=ipset_{name}.txt",
    }
    return (body, 200, headers)


@app.route("/settings/pve", methods=["GET", "POST"])
@login_required
def settings_pve():
    if request.method == "GET":
        return render_template("settings_pve.html", settings=settings.pve, message=None)

    # POST
    host = request.form.get("host", "")
    user = request.form.get("user", "")
    password = request.form.get("password", "")
    ssl_verify = request.form.get("ssl_verify") == "on"
    protocol = request.form.get("protocol") or None
    port_str = request.form.get("port")
    port = int(port_str) if (port_str and port_str.isdigit()) else None
    token_name = request.form.get("token_name") or None
    token_value = request.form.get("token_value") or None
    settings.update_pve(host, user, password, ssl_verify, protocol=protocol, port=port, token_name=token_name, token_value=token_value)
    # Reset cached clients; will reconnect on demand next time
    global proxmox, firewall
    proxmox = None
    firewall = None
    message = "PVE settings updated"
    return render_template("settings_pve.html", settings=settings.pve, message=message)


@app.route("/settings/tencent", methods=["GET", "POST"])
@login_required
def settings_tencent():
    message = None
    if request.method == "POST":
        secret = request.form.get("secret", "")
        key = request.form.get("key", "")
        settings.update_tencent(secret, key)
        message = "Tencent settings updated"
    return render_template(
        "settings_tencent.html", settings=settings.tencent, message=message
    )


# 入口在 main.py 中统一启动


@app.route("/api/test/pve", methods=["POST"])
@login_required
def api_test_pve():
    data = request.get_json(silent=True) or {}
    # 使用传入参数优先，其次落到已保存配置
    conf = {
        "host": (data.get("host") or settings.pve.get("host") or "").strip(),
        "user": data.get("user") or settings.pve.get("user"),
        "password": data.get("password") or settings.pve.get("password"),
        "ssl_verify": bool(
            data.get("ssl_verify") if data.get("ssl_verify") is not None else settings.pve.get("ssl_verify", True)
        ),
        "protocol": (data.get("protocol") or settings.pve.get("protocol") or "https").lower(),
        "port": data.get("port") or settings.pve.get("port") or 8006,
        "token_name": (data.get("token_name") or settings.pve.get("token_name") or "").strip(),
        "token_value": (data.get("token_value") or settings.pve.get("token_value") or "").strip(),
        "otp": (data.get("otp") or "").strip(),
    }
    host, protocol, port = _normalize_host_port_protocol(conf["host"], conf["protocol"], int(conf["port"]))
    if not conf["host"]:
        return jsonify({"ok": False, "message": "PVE 未配置或主机名为空"}), 400
    try:
        # 惰性创建客户端并调用需要鉴权的接口进行验证
        if conf["token_value"]:
            log_proxmox_init("api_test_pve", host, port, conf["ssl_verify"], conf["user"], conf["token_name"], using_token=True, otp_value=None)
            client = ProxmoxAPI(
                host=host,
                user=conf["user"],
                token_name=conf["token_name"],
                token_value=conf["token_value"],
                verify_ssl=conf["ssl_verify"],
                port=port,
                timeout=5,
            )
        else:
            log_proxmox_init("api_test_pve", host, port, conf["ssl_verify"], conf["user"], conf["token_name"], using_token=False, otp_value=(conf.get('otp') or None))
            client = ProxmoxAPI(
                host=host,
                user=conf["user"],
                password=conf["password"],
                verify_ssl=conf["ssl_verify"],
                port=port,
                timeout=5,
                otp=(conf["otp"] or None),
            )
        nodes = client.nodes.get()  # 需要鉴权
        return jsonify({
            "ok": True,
            "message": f"连接成功，检测到 {len(nodes)} 个节点",
        })
    except Exception as e:  # noqa: BLE001 - 返回错误信息给前端
        return jsonify({"ok": False, "message": f"连接失败：{e}"}), 200


@app.route("/api/test/tencent", methods=["POST"])
@login_required
def api_test_tencent():
    data = request.get_json(silent=True) or {}
    secret = (data.get("secret") or settings.tencent.get("secret") or "").strip()
    key = (data.get("key") or settings.tencent.get("key") or "").strip()
    if not secret or not key:
        return jsonify({"ok": False, "message": "请填写 Secret 与 Key"}), 400
    try:
        # 延迟导入以减少非必要依赖加载
        from tencentcloud.common import credential
        from tencentcloud.cvm.v20170312 import cvm_client, models

        cred = credential.Credential(secret, key)
        client = cvm_client.CvmClient(cred, "ap-guangzhou")
        req = models.DescribeRegionsRequest()
        _ = client.DescribeRegions(req)
        return jsonify({"ok": True, "message": "凭据有效，可访问腾讯云 API"})
    except Exception as e:  # noqa: BLE001
        return jsonify({"ok": False, "message": f"验证失败：{e}"}), 200
