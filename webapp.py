from functools import wraps
from ipaddress import ip_network

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
)
from proxmoxer import ProxmoxAPI

from config import (
    WEB_USERNAME,
    WEB_PASSWORD,
    FLASK_SECRET_KEY,
)
from modules.firewall import Firewall
from modules.settings import Settings


app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

settings = Settings()


def create_proxmox() -> ProxmoxAPI | None:
    pve_conf = settings.pve
    host = (pve_conf.get("host") or "").strip()
    user = pve_conf.get("user")
    password = pve_conf.get("password")
    verify_ssl = bool(pve_conf.get("ssl_verify", True))
    if not host:
        return None
    return ProxmoxAPI(host=host, user=user, password=password, verify_ssl=verify_ssl)

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
    message = None
    ipset_name = "whitelist"
    if request.method == "POST":
        ip = request.form.get("ip", "")
        try:
            network = ip_network(ip, strict=False)
            fw = get_firewall()
            if fw is None:
                message = "PVE 未配置，请先到设置页面配置。"
            else:
                ipsets = [i["name"] for i in fw.get_ipsets()]
                if ipset_name not in ipsets:
                    fw.create_ipset(ipset_name, [network])
                else:
                    current = [ip_network(i) for i in fw.check_ipset(ipset_name)]
                    current.append(network)
                    fw.update_ipset(ipset_name, current)
                message = "IP added successfully"
        except ValueError:
            message = "Invalid IP address"
    fw = get_firewall()
    if fw is None:
        ipsets = []
        existing_ips = []
    else:
        ipsets = [i["name"] for i in fw.get_ipsets()]
        existing_ips = fw.check_ipset(ipset_name) if ipset_name in ipsets else []
    return render_template("whitelist.html", ips=existing_ips, message=message)


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
    settings.update_pve(host, user, password, ssl_verify)
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
