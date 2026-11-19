# Custom Domain & Reverse Proxy Deployment Guide

This guide describes how to attach a custom domain to the TRAC Threat Response & Analysis Command Platform using Nginx or Caddy.

## Prerequisites

1. A registered domain name (e.g. `trac.your-soc.org`).
2. An A or CNAME DNS record pointing to your server's public IP address.
3. TLS/SSL certificates (e.g. via Let's Encrypt / Certbot).
4. TRAC backend running on `127.0.0.1:8088` (or your configured `TRAC_UI_PORT`).

## Environment Configuration

Configure your environment variables in `.env` to authorize the custom domain:

```bash
# Bind interface (keep 127.0.0.1 when behind a reverse proxy)
TRAC_UI_HOST=127.0.0.1
TRAC_UI_PORT=8088

# Allowed origins for CORS (comma-separated origins)
TRAC_UI_ALLOWED_ORIGINS=https://trac.your-soc.org,https://api.trac.your-soc.org
```

## Nginx Deployment

1. Copy `reverse_proxy/nginx.conf` to `/etc/nginx/sites-available/trac.conf`.
2. Edit `/etc/nginx/sites-available/trac.conf` to set `server_name` to your domain.
3. Obtain SSL certificates:
   ```bash
   sudo certbot --nginx -d trac.your-soc.org
   ```
4. Enable the configuration and reload Nginx:
   ```bash
   sudo ln -s /etc/nginx/sites-available/trac.conf /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl reload nginx
   ```

## Key Considerations

- **Upload Limit**: The `client_max_body_size 105M;` directive ensures that 100 MiB sample uploads are permitted without being truncated by Nginx.
- **Timeouts**: Heavy sandbox operations and dynamic polling require extended read timeouts (`120s`).
- **Security Headers**: HSTS, nosniff, and strict referrer policies are configured by default.
