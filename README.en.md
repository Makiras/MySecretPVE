# MySecretPVE

A lightweight Flask web app to manage Proxmox VE cluster firewall IPSets. Built with Flask + proxmoxer and persists settings (PVE/Tencent credentials) in SQLite via SQLAlchemy.

## Features

- IPSet management: create, delete, rename, edit comment, add/remove entries, bulk import/remove, export as text
- Authentication: simple username/password login from `config.py`
- Proxmox connectivity: password or API Token auth, SSL verify toggle, custom port
- Connectivity tests: `POST /api/test/pve` and `POST /api/test/tencent`
- Persistent settings: auto-create `settings.db` with light migrations
- Optional verbose HTTP logging for debugging

## Requirements

- Python 3.10+
- Network access to your Proxmox VE API endpoint

## Install & Run

1) Install dependencies

```bash
pip install -r requirements.txt
```

2) Configure basics (strongly recommended)

- Edit `config.py`:
  - `WEB_USERNAME` / `WEB_PASSWORD`: web login (defaults `admin`/`password`)
  - `FLASK_SECRET_KEY`: session signing key
  - `ENABLE_HTTP_DEBUG` / `ENABLE_HTTP_DEBUG_SHOW_SECRETS`: debug switches (can also be set via env)

3) Start the dev server

```bash
python main.py
# Open http://localhost:5000
```

4) Production example (Gunicorn)

```bash
pip install gunicorn
gunicorn -w 2 -b 0.0.0.0:5000 webapp:app
```

## Deployment

- Ubuntu + Nginx + systemd: see `docs/DEPLOYMENT_UBUNTU_NGINX.md`.
- Sample configs: `deploy/mysecretpve.service`, `deploy/nginx/mysecretpve.conf`.

## Usage

- Login using credentials from `config.py`
- Dashboard shows whether PVE is configured
- IPSet pages:
  - List: create/delete IPSets
  - Detail: add/remove IP or CIDR, bulk import/remove, rename, edit comment, export `.txt`
- Settings pages:
  - PVE: `host`, `user`, `password`, `ssl_verify`, `protocol`, `port`, `token_name`/`token_value`
    - Host can be `https://host:8006`, `host:8006`, `[2001:db8::1]:8006`, etc. The app normalizes and stores host/port.
    - API Token is preferred over password if provided
  - Tencent: `secret`, `key` (for credential validation and future extensions)

## API (for testing)

- POST `/api/test/pve`: verify connectivity and auth with PVE
  - Body (JSON, only override what you need):
    ```json
    {
      "host": "https://pve.example.com:8006",
      "user": "root@pam",
      "password": "...",
      "ssl_verify": true,
      "protocol": "https",
      "port": 8006,
      "token_name": "mytoken@pve",
      "token_value": "...",
      "otp": "optional one-time password"
    }
    ```
  - Returns node count on success

- POST `/api/test/tencent`: validate Tencent Cloud credentials
  - Body (JSON): `{"secret": "...", "key": "..."}` (falls back to saved values)

## Project Structure

```
.
├── main.py               # Entry point: start Flask app
├── webapp.py             # Routes, PVE client, views
├── modules/
│   ├── firewall.py       # proxmoxer-based firewall/IPSet wrapper
│   ├── settings.py       # SQLAlchemy models and Settings persistence
│   ├── cloudflare.py     # Cloudflare IP ranges (optional)
│   ├── tencent.py        # Tencent CDN/domain helpers (optional)
│   └── ipranger.py       # Public IPv4/IPv6 fetcher (utility)
├── templates/            # Jinja2 templates
├── requirements.txt      # Dependencies
├── config.py             # Login and debug config
└── settings.db           # SQLite database (auto-created)
```

## Debugging & Logs

- Enable verbose HTTP/proxmoxer logs via env:
  ```bash
  export HTTP_DEBUG=1
  # Show sensitive values in logs (not recommended):
  export HTTP_DEBUG_SHOW_SECRETS=1
  ```
  Or set corresponding flags in `config.py`.

## Security Notes

- Change default login and `FLASK_SECRET_KEY` before deploying
- Prefer API Tokens with least privilege for PVE access
- Enable `ssl_verify` and configure CA certificates in production
- Protect `settings.db` as it contains sensitive data

## License

Apache License 2.0. See `LICENSE` for details.

## Acknowledgements

- proxmoxer, Flask, SQLAlchemy, and the wider open-source ecosystem
