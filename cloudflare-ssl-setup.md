# CloudFlare SSL Setup Guide

## 1. Generate CloudFlare Origin Certificate

1. Log into CloudFlare dashboard
2. Go to SSL/TLS → Origin Server
3. Click "Create Certificate"
4. Select "Let CloudFlare generate a private key and a CSR"
5. Add hostnames: `calc.istormsolutions.online`, `*.istormsolutions.online`
6. Set certificate validity (15 years recommended)
7. Click "Create"

## 2. Save Certificate Files on Server

### Create certificate file:
```bash
sudo mkdir -p /etc/ssl/certs
sudo nano /etc/ssl/certs/calc.istormsolutions.online.pem
```
Paste the Origin Certificate content (including BEGIN/END lines)

### Create private key file:
```bash
sudo mkdir -p /etc/ssl/private
sudo nano /etc/ssl/private/calc.istormsolutions.online.key
```
Paste the Private Key content (including BEGIN/END lines)

### Set proper permissions:
```bash
sudo chmod 644 /etc/ssl/certs/calc.istormsolutions.online.pem
sudo chmod 600 /etc/ssl/private/calc.istormsolutions.online.key
sudo chown root:root /etc/ssl/certs/calc.istormsolutions.online.pem
sudo chown root:root /etc/ssl/private/calc.istormsolutions.online.key
```

## 3. CloudFlare Dashboard Settings

### SSL/TLS Settings:
- **Overview**: Set to "Full (strict)"
- **Edge Certificates**: Enable "Always Use HTTPS"
- **Edge Certificates**: Enable "HTTP Strict Transport Security (HSTS)"

### DNS Settings:
- Add A record: `calc` pointing to your server IP
- Enable CloudFlare proxy (orange cloud icon)

### Security Settings:
- **Firewall → Security Level**: Medium or High
- **Scrape Shield**: Enable Email Address Obfuscation
- **Scrape Shield**: Enable Server-side Excludes

## 4. Test SSL Configuration

```bash
# Test SSL certificate
openssl x509 -in /etc/ssl/certs/calc.istormsolutions.online.pem -text -noout

# Test nginx configuration
sudo nginx -t

# Restart nginx
sudo systemctl restart nginx

# Check SSL rating
# Visit: https://www.ssllabs.com/ssltest/analyze.html?d=calc.istormsolutions.online
```

## 5. Firewall Configuration

```bash
# Allow HTTPS traffic
sudo ufw allow 443/tcp
sudo ufw allow 80/tcp

# Reload firewall
sudo ufw reload
```

## 6. Verification Steps

1. Visit https://calc.istormsolutions.online
2. Check for green padlock in browser
3. Verify certificate shows "CloudFlare Inc ECC CA-3"
4. Test automatic HTTP to HTTPS redirect
5. Run SSL test at ssllabs.com

## Security Benefits

- **DDoS Protection**: CloudFlare's network shields your origin server
- **WAF**: Web Application Firewall filters malicious requests
- **Rate Limiting**: Additional protection at CloudFlare edge
- **Real IP**: nginx gets visitor's real IP address
- **Caching**: Static assets cached at CloudFlare edge servers