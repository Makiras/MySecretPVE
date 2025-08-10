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


def create_proxmox() -> ProxmoxAPI:
    return ProxmoxAPI(
        host=settings.pve["host"],
        user=settings.pve["user"],
        password=settings.pve["password"],
        verify_ssl=settings.pve["ssl_verify"],
    )


proxmox = create_proxmox()
firewall = Firewall(proxmox)


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
    return render_template("dashboard.html")


@app.route("/whitelist", methods=["GET", "POST"])
@login_required
def whitelist():
    message = None
    ipset_name = "whitelist"
    if request.method == "POST":
        ip = request.form.get("ip", "")
        try:
            network = ip_network(ip, strict=False)
            ipsets = [i["name"] for i in firewall.get_ipsets()]
            if ipset_name not in ipsets:
                firewall.create_ipset(ipset_name, [network])
            else:
                current = [ip_network(i) for i in firewall.check_ipset(ipset_name)]
                current.append(network)
                firewall.update_ipset(ipset_name, current)
            message = "IP added successfully"
        except ValueError:
            message = "Invalid IP address"
    ipsets = [i["name"] for i in firewall.get_ipsets()]
    existing_ips = (
        firewall.check_ipset(ipset_name) if ipset_name in ipsets else []
    )
    return render_template("whitelist.html", ips=existing_ips, message=message)


@app.route("/settings/pve", methods=["GET", "POST"])
@login_required
def settings_pve():
    message = None
    if request.method == "POST":
        host = request.form.get("host", "")
        user = request.form.get("user", "")
        password = request.form.get("password", "")
        ssl_verify = request.form.get("ssl_verify") == "on"
        settings.update_pve(host, user, password, ssl_verify)
        global proxmox, firewall
        proxmox = create_proxmox()
        firewall = Firewall(proxmox)
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
