# Quote Calculator - AWS Deployment Guide

## Security Features Implemented

### ✓ OWASP Top 10 Security Compliance
- **A01 - Broken Access Control**: Role-based access with proper authentication
- **A02 - Cryptographic Failures**: Bcrypt password hashing, secure session management
- **A03 - Injection**: Input sanitization with bleach, parameterized queries
- **A04 - Insecure Design**: Secure architecture with rate limiting and validation
- **A05 - Security Misconfiguration**: Security headers, CSRF protection
- **A06 - Vulnerable Components**: Updated dependencies, security patches
- **A07 - Authentication Failures**: Account lockout, brute force protection
- **A08 - Software Integrity**: Secure deployment process
- **A09 - Security Logging**: Login attempt tracking
- **A10 - Server-Side Request Forgery**: Input validation and sanitization

### ✓ Implemented Security Measures
- **Rate Limiting**: 50 requests/minute globally, specific limits per endpoint
- **Brute Force Protection**: 5 failed attempts = 15-minute account lockout
- **IP-based Protection**: 10 failed attempts from same IP = temporary block
- **Username Enumeration Prevention**: Generic error messages
- **Strong Password Policy**: 12+ characters, mixed case, numbers, symbols
- **Input Sanitization**: All user inputs cleaned and validated
- **CSRF Protection**: Token-based protection on all forms
- **Security Headers**: XSS, clickjacking, content-type protection
- **Session Security**: Secure session management with timeouts
- **Database Security**: Parameterized queries, no SQL injection

## AWS Deployment Instructions

### Prerequisites
- AWS EC2 instance (Ubuntu 20.04+ recommended)
- Domain name configured with CloudFlare (recommended)
- SSH access to your EC2 instance

### Step 1: Upload Application

1. **Create deployment package**:
   ```bash
   # On your local machine
   cd /path/to/quote_calculator_v2
   zip -r quote_calculator_v2.zip . -x "venv/*" "instance/*" "*.pyc" "__pycache__/*" ".git/*"
   ```

2. **Upload to AWS**:
   ```bash
   scp quote_calculator_v2.zip ubuntu@your-server-ip:~/
   ```

### Step 2: Server Setup

1. **Connect to your server**:
   ```bash
   ssh ubuntu@your-server-ip
   ```

2. **Update system and install dependencies**:
   ```bash
   sudo apt update && sudo apt upgrade -y
   sudo apt install python3 python3-pip python3-venv nginx unzip -y
   ```

3. **Extract and setup application**:
   ```bash
   cd ~
   unzip quote_calculator_v2.zip -d quote_calculator_v2
   cd quote_calculator_v2
   ```

4. **Configure environment**:
   ```bash
   # Copy and edit environment file
   cp .env.example .env
   nano .env  # Edit with your secure settings
   ```

   **Important**: Change `FLASK_SECRET_KEY` to a secure random value:
   ```bash
   python3 -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

5. **Run the application**:
   ```bash
   chmod +x start.sh
   ./start.sh
   ```

### Step 3: Configure Nginx (Production)

1. **Create Nginx configuration**:
   ```bash
   sudo nano /etc/nginx/sites-available/quote_calculator
   ```

   Add this configuration:
   ```nginx
   server {
       listen 80;
       server_name your-domain.com;
       
       # Security headers
       add_header X-Frame-Options DENY;
       add_header X-Content-Type-Options nosniff;
       add_header X-XSS-Protection "1; mode=block";
       add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
       
       # Rate limiting
       limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
       limit_req_zone $binary_remote_addr zone=api:10m rate=50r/m;
       
       location / {
           limit_req zone=api burst=20 nodelay;
           proxy_pass http://127.0.0.1:5001;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
       
       location /login {
           limit_req zone=login burst=5 nodelay;
           proxy_pass http://127.0.0.1:5001;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
       
       location /register {
           limit_req zone=login burst=3 nodelay;
           proxy_pass http://127.0.0.1:5001;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```

2. **Enable the site**:
   ```bash
   sudo ln -s /etc/nginx/sites-available/quote_calculator /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl reload nginx
   ```

### Step 4: Set up SSL with Let's Encrypt

```bash
sudo apt install certbot python3-certbot-nginx -y
sudo certbot --nginx -d your-domain.com
```

### Step 5: Create System Service

1. **Create systemd service**:
   ```bash
   sudo nano /etc/systemd/system/quote_calculator.service
   ```

   Add this content:
   ```ini
   [Unit]
   Description=Quote Calculator Flask App
   After=network.target
   
   [Service]
   Type=simple
   User=ubuntu
   WorkingDirectory=/home/ubuntu/quote_calculator_v2
   Environment=PATH=/home/ubuntu/quote_calculator_v2/venv/bin
   ExecStart=/home/ubuntu/quote_calculator_v2/venv/bin/gunicorn -w 4 -b 127.0.0.1:5001 app:app
   Restart=always
   RestartSec=10
   
   [Install]
   WantedBy=multi-user.target
   ```

2. **Enable and start service**:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable quote_calculator
   sudo systemctl start quote_calculator
   sudo systemctl status quote_calculator
   ```

### Step 6: Security Hardening

1. **Configure firewall**:
   ```bash
   sudo ufw allow 22/tcp
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   sudo ufw --force enable
   ```

2. **Set up fail2ban**:
   ```bash
   sudo apt install fail2ban -y
   sudo systemctl enable fail2ban
   sudo systemctl start fail2ban
   ```

3. **Configure CloudFlare** (Recommended):
   - Set up CloudFlare for your domain
   - Enable DDoS protection
   - Configure Web Application Firewall (WAF)
   - Set up rate limiting rules

### Step 7: Monitoring and Maintenance

1. **Check application logs**:
   ```bash
   sudo journalctl -u quote_calculator -f
   ```

2. **Monitor system resources**:
   ```bash
   htop
   df -h
   ```

3. **Regular updates**:
   ```bash
   sudo apt update && sudo apt upgrade -y
   sudo systemctl restart quote_calculator
   ```

### Troubleshooting

- **Application won't start**: Check logs with `sudo journalctl -u quote_calculator`
- **Database issues**: Ensure proper permissions on database file
- **Rate limiting issues**: Check nginx error logs with `sudo tail -f /var/log/nginx/error.log`
- **SSL certificate issues**: Run `sudo certbot renew --dry-run`

### Security Notes

- ⚠️ **Never commit .env file to version control**
- ⚠️ **Change default SECRET_KEY in production**
- ⚠️ **Regularly update dependencies**
- ⚠️ **Monitor login attempts and failed authentications**
- ⚠️ **Use strong passwords for all accounts**
- ⚠️ **Keep system and packages updated**

This deployment setup provides enterprise-grade security suitable for public internet hosting.