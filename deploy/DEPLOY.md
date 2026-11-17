# Deploying StressScope to a WHM / cPanel server

StressScope is a **Python FastAPI app** (not PHP). It uses uvicorn (ASGI), a
WebSocket live feed, and **Playwright** (a real headless Chromium). cPanel's
"Setup Python App" (Passenger/WSGI) cannot run the ASGI app + WebSockets
cleanly, so the reliable pattern on a WHM box (where you have root) is:

```
subdomain (Apache vhost + AutoSSL)  ->  reverse proxy  ->  uvicorn @127.0.0.1:8765  (systemd service)
```

All commands below run as **root over SSH**. Replace the placeholders:
`CPUSER` (cPanel account), `stress.example.com` (your subdomain).

---

## 0. Create the subdomain in cPanel first

In the target cPanel account: **Domains -> Create a New Domain** ->
`stress.example.com`. Let AutoSSL issue a cert for it (or do step 6 later).
This makes WHM generate the vhost we will attach the proxy include to.

## 1. Install Python 3.11+ and Playwright's system libraries (root)

The stock `python3` on AlmaLinux/CloudLinux 8 is too old. Install a modern one:

```bash
dnf install -y python3.11 python3.11-pip git
```

Playwright needs OS libraries for Chromium. Easiest is to let Playwright pull
them in step 3 with `playwright install-deps`; it runs `dnf` and needs root.

> CloudLinux note: don't use the cPanel "Python Selector" (alt-python) for this —
> it's sandboxed per user and can't install system libs. Use the real
> `python3.11` above for the systemd service.

## 2. Create a service user and deploy the code

```bash
useradd -r -m -d /opt/stressscope -s /sbin/nologin stressscope
cd /opt/stressscope
# Option A: clone from your git remote
git clone <YOUR_REPO_URL> .
# Option B: upload the folder (minus data/, .venv/) with rsync/scp, then:
#   chown -R stressscope:stressscope /opt/stressscope
```

## 3. Virtualenv, dependencies, and the Chromium browser

```bash
cd /opt/stressscope
sudo -u stressscope python3.11 -m venv .venv
sudo -u stressscope .venv/bin/pip install --upgrade pip
sudo -u stressscope .venv/bin/pip install -r requirements.txt

# Install deps as root (writes to /usr via dnf), then the browser as the user:
.venv/bin/playwright install-deps chromium
sudo -u stressscope PLAYWRIGHT_BROWSERS_PATH=/opt/stressscope/.cache/ms-playwright \
    .venv/bin/playwright install chromium

chown -R stressscope:stressscope /opt/stressscope
```

Quick smoke test (Ctrl+C to stop):

```bash
sudo -u stressscope PLAYWRIGHT_BROWSERS_PATH=/opt/stressscope/.cache/ms-playwright \
    .venv/bin/uvicorn app:app --host 127.0.0.1 --port 8765
```

## 4. Run uvicorn as a systemd service

```bash
cp /opt/stressscope/deploy/stressscope.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now stressscope
systemctl status stressscope          # should be active (running)
curl -I http://127.0.0.1:8765/         # should return 200
```

## 5. Attach the reverse proxy to the cPanel vhost

Do **not** edit `httpd.conf` directly — cPanel regenerates it. Use a userdata
include so the config survives rebuilds:

```bash
D=/etc/apache2/conf.d/userdata
mkdir -p $D/std/2_4/CPUSER/stress.example.com
mkdir -p $D/ssl/2_4/CPUSER/stress.example.com
cp /opt/stressscope/deploy/stressscope-proxy.conf \
   $D/std/2_4/CPUSER/stress.example.com/stressscope.conf
cp /opt/stressscope/deploy/stressscope-proxy.conf \
   $D/ssl/2_4/CPUSER/stress.example.com/stressscope.conf

# Make sure the proxy/wstunnel modules are on (WHM -> EasyApache 4 also works)
/scripts/ensure_vhost_includes --user=CPUSER
/scripts/rebuildhttpdconf
systemctl restart httpd
```

Visit `https://stress.example.com` — the StressScope UI should load and the
live WebSocket feed should connect during a scan.

## 6. SSL

If AutoSSL hasn't already covered the subdomain: WHM -> **SSL/TLS** ->
**Manage AutoSSL** -> Run AutoSSL for CPUSER. The `ssl/...` include above
applies the same proxy to the HTTPS vhost.

---

## IMPORTANT: lock it down

StressScope launches load tests and security scans against whatever URL is
entered. Left open on a public subdomain, anyone can drive it. At minimum put
HTTP Basic Auth in front. Add to `deploy/stressscope-proxy.conf` (both copies)
**above** the `ProxyPass` lines:

```apache
<Location />
    AuthType Basic
    AuthName "StressScope"
    AuthUserFile /opt/stressscope/.htpasswd
    Require valid-user
</Location>
```

Create the password file, then rebuild httpd:

```bash
htpasswd -c /opt/stressscope/.htpasswd youradmin
```

Also consider a firewall rule so port 8765 is never reachable from outside
(it binds to 127.0.0.1 already, so it shouldn't be — verify with
`ss -ltnp | grep 8765`).

> Running outbound stress/load tests from a hosting IP can violate your
> provider's AUP and get the server flagged. Point it only at targets you own.

---

## Updating later

```bash
cd /opt/stressscope && sudo -u stressscope git pull
sudo -u stressscope .venv/bin/pip install -r requirements.txt
systemctl restart stressscope
```

## Troubleshooting

| Symptom | Check |
|---|---|
| 503 from Apache | `systemctl status stressscope`; is uvicorn up on 8765? |
| Scans fail instantly | Playwright browser/libs: rerun step 3; `journalctl -u stressscope` |
| WebSocket won't connect | `proxy_wstunnel` module loaded? `httpd -M | grep wstunnel` |
| Permission denied on browser | `PLAYWRIGHT_BROWSERS_PATH` owned by `stressscope`? |
