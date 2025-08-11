# Deployment: Ubuntu + Nginx + systemd

This guide describes a production-ready deployment of MySecretPVE on Ubuntu using Nginx as a reverse proxy and systemd to manage Gunicorn.

## Prerequisites

- Ubuntu 20.04/22.04+ with sudo access
- A domain pointing to your server (optional but recommended)
- Installed packages:
  ```bash
  sudo apt update
  sudo apt install -y python3-venv python3-pip git nginx
  ```

## 1) Create directories and user

```bash
sudo mkdir -p /opt/mysecretpve
sudo useradd --system --home /opt/mysecretpve --shell /usr/sbin/nologin --gid www-data mysecretpve || true
sudo chown -R mysecretpve:www-data /opt/mysecretpve
```

## 2) Fetch code and set up virtualenv

```bash
sudo -u mysecretpve bash -lc '
  cd /opt/mysecretpve
  git clone <repo-url> app
  python3 -m venv venv
  source venv/bin/activate
  pip install --upgrade pip
  pip install -r app/requirements.txt
  pip install gunicorn
'
```

Replace `<repo-url>` with your repository URL.

## 3) Configure the application

Edit `app/config.py` and set secure values:
- `WEB_USERNAME`, `WEB_PASSWORD`
- `FLASK_SECRET_KEY`
- Optional: `ENABLE_HTTP_DEBUG`, `ENABLE_HTTP_DEBUG_SHOW_SECRETS`

Ensure the app directory is writable by the service user (for `settings.db`):
```bash
sudo chown -R mysecretpve:www-data /opt/mysecretpve
```

## 4) systemd service (Gunicorn)

Create a unit file: `/etc/systemd/system/mysecretpve.service`

```
[Unit]
Description=MySecretPVE (Gunicorn)
After=network.target

[Service]
User=mysecretpve
Group=www-data
WorkingDirectory=/opt/mysecretpve/app
Environment=PYTHONPATH=/opt/mysecretpve/app
Environment=HTTP_DEBUG=0
RuntimeDirectory=mysecretpve
RuntimeDirectoryMode=0755
UMask=007
ExecStart=/opt/mysecretpve/venv/bin/gunicorn \
  --workers 2 \
  --timeout 30 \
  --bind unix:/run/mysecretpve/gunicorn.sock \
  webapp:app
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Or copy the sample unit from this repo:

```bash
sudo cp deploy/mysecretpve.service /etc/systemd/system/mysecretpve.service
sudo systemctl daemon-reload
sudo systemctl enable --now mysecretpve
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mysecretpve
sudo systemctl status mysecretpve --no-pager
```

Logs:
```bash
journalctl -u mysecretpve -f
```

## 5) Nginx reverse proxy

Create `/etc/nginx/sites-available/mysecretpve`:

```
server {
    listen 80;
    server_name your.domain.tld;  # change to your domain or server IP

    # Increase if you upload large payloads
    client_max_body_size 10m;

    location / {
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_redirect off;
        proxy_pass http://unix:/run/mysecretpve/gunicorn.sock;
    }
}
```

Enable the site and reload Nginx:
```bash
sudo ln -s /etc/nginx/sites-available/mysecretpve /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

Or copy the sample site config from this repo:

```bash
sudo cp deploy/nginx/mysecretpve.conf /etc/nginx/sites-available/mysecretpve
sudo ln -s /etc/nginx/sites-available/mysecretpve /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

## 6) HTTPS (Let’s Encrypt)

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d your.domain.tld
```

## 7) Upgrades

```bash
sudo systemctl stop mysecretpve
sudo -u mysecretpve bash -lc '
  cd /opt/mysecretpve/app
  git pull --ff-only
  source ../venv/bin/activate
  pip install -r requirements.txt
'
sudo systemctl start mysecretpve
```

## 8) Backups

- Backup `/opt/mysecretpve/app/settings.db` regularly.
- Consider backing up `config.py` if customized.

## 9) Troubleshooting

- `502 Bad Gateway` in Nginx: check service status and socket path permissions (`Group=www-data`, `UMask=007`).
- Permission errors on `settings.db`: ensure ownership `mysecretpve:www-data` and writable directory.
- Connection failures to PVE: verify network reachability, SSL settings, and try `/api/test/pve`.
