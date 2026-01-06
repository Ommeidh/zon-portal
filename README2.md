# Zon Portal - Server Restart & Maintenance Guide

## Quick Reference Commands

```bash
# SSH into server
gcloud compute ssh zon-portal --zone=us-central1-a

# Or with standard SSH
ssh ommeidh@34.10.48.57
```

---

## Restarting the App

### After Code Changes
```bash
# Upload new files first (from your local machine)
scp app.py ommeidh@zon-productions.com:~/zon-portal/
scp templates/*.html ommeidh@zon-productions.com:~/zon-portal/templates/

# Then on server, restart the service
sudo systemctl restart zon-portal
```

### Quick Restart
```bash
sudo systemctl restart zon-portal
```

### Check Status
```bash
sudo systemctl status zon-portal
```

---

## Restarting Nginx

```bash
# Restart
sudo systemctl restart nginx

# Test config first
sudo nginx -t

# Reload (no downtime)
sudo systemctl reload nginx
```

---

## If Server Rebooted

Everything should auto-start. If not:

```bash
# Start services
sudo systemctl start nginx
sudo systemctl start zon-portal

# Check they're enabled for auto-start
sudo systemctl enable nginx
sudo systemctl enable zon-portal
```

---

## Viewing Logs

```bash
# App logs
sudo journalctl -u zon-portal -f

# Last 100 lines
sudo journalctl -u zon-portal -n 100

# Nginx access logs
sudo tail -f /var/log/nginx/access.log

# Nginx error logs
sudo tail -f /var/log/nginx/error.log
```

---

## Common Issues

### Port Already in Use
```bash
sudo pkill -f gunicorn
sudo systemctl restart zon-portal
```

### 502 Bad Gateway
App isn't running:
```bash
sudo systemctl status zon-portal
sudo systemctl restart zon-portal
```

### SSL Certificate Expired
```bash
sudo certbot renew
sudo systemctl reload nginx
```

### Check What's Running
```bash
# See what's on port 5000
sudo ss -tlnp | grep 5000

# See all running services
systemctl list-units --type=service --state=running
```

---

## Updating the App

### 1. Upload New Files
From your local machine:
```bash
# Single file
scp app.py ommeidh@zon-productions.com:~/zon-portal/

# All templates
scp templates/*.html ommeidh@zon-productions.com:~/zon-portal/templates/

# Or entire folder
scp -r zon-portal/* ommeidh@zon-productions.com:~/zon-portal/
```

### 2. Restart Service
```bash
sudo systemctl restart zon-portal
```

### 3. Verify
```bash
sudo systemctl status zon-portal
curl http://localhost:5000
```

---

## Backup Database

```bash
# Create backup
cp ~/zon-portal/users.db ~/zon-portal/users.db.backup.$(date +%Y%m%d)

# Download to local machine
scp ommeidh@zon-productions.com:~/zon-portal/users.db ./users.db.backup
```

---

## Update Game File

```bash
# From Google Drive
cd ~/zon-portal/downloads
gdown "https://drive.google.com/uc?id=YOUR_FILE_ID" -O NightShadow.zip

# Or via rsync (resumable)
rsync -avP NightShadow.zip ommeidh@zon-productions.com:~/zon-portal/downloads/
```

---

## Renew SSL Certificate

Certbot auto-renews, but to manually renew:
```bash
sudo certbot renew
sudo systemctl reload nginx
```

Check expiry:
```bash
sudo certbot certificates
```

---

## Full Server Restart Procedure

If you need to completely restart everything:

```bash
# 1. Stop services
sudo systemctl stop zon-portal
sudo systemctl stop nginx

# 2. Start services
sudo systemctl start nginx
sudo systemctl start zon-portal

# 3. Verify
sudo systemctl status nginx
sudo systemctl status zon-portal
curl http://localhost
```

---

## Important Paths

| What | Path |
|------|------|
| App code | `~/zon-portal/app.py` |
| Templates | `~/zon-portal/templates/` |
| Config | `~/zon-portal/.env` |
| Database | `~/zon-portal/users.db` |
| Game file | `~/zon-portal/downloads/NightShadow.zip` |
| Nginx config | `/etc/nginx/sites-available/zon-portal` |
| Service file | `/etc/systemd/system/zon-portal.service` |
| SSL certs | `/etc/letsencrypt/live/zon-productions.com/` |

---

## Security Reminders

- Admin URL: `https://zon-productions.com/YOUR_ADMIN_URL/login`
- Keep ADMIN_URL secret - don't share it
- Admin password is in `~/zon-portal/.env`
- Rate limiting: 5 login attempts per minute
- Backup database regularly

---

## Emergency: Site Down

1. SSH into server
2. Check nginx: `sudo systemctl status nginx`
3. Check app: `sudo systemctl status zon-portal`
4. Check logs: `sudo journalctl -u zon-portal -n 50`
5. Restart both: `sudo systemctl restart nginx zon-portal`
6. Test: `curl http://localhost`