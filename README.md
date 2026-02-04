# Quote Calculator

A modern, secure web application for generating security assessment quotes. Built with Flask, PostgreSQL, and Docker.

## Features

- **Quote Generation**: Calculate estimated days for security assessments
  - Web Application Testing
  - External/Internal Infrastructure
  - API Security
  - Mobile Application Testing
  - Cloud Security (AWS, Azure, GCP)
  - Kubernetes & Docker
  - Office 365 Assessment
  - Wi-Fi Assessment
  - Red Team Engagements

- **User Management**
  - Role-based access control
  - Secure password requirements (12+ chars, mixed case, numbers, special chars)
  - Account lockout protection
  - Password reset via email

- **Customization**
  - Company branding (logo, name)
  - Multiple color schemes
  - Configurable email domain restriction

- **Security**
  - CSRF protection
  - Rate limiting
  - Input sanitization
  - Comprehensive audit logging

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Nginx Proxy Manager (or similar reverse proxy) for SSL

### Deployment

1. **Clone and configure**
   ```bash
   git clone <repository-url>
   cd quote-calculator
   cp .env.example .env
   ```

2. **Edit `.env`**
   ```bash
   # Generate a secret key
   python -c "import secrets; print(secrets.token_hex(32))"
   ```

   Set these values in `.env`:
   - `FLASK_SECRET_KEY` - paste the generated key
   - `POSTGRES_PASSWORD` - set a secure database password
   - `BASE_URL` - your subdomain (e.g., `https://quotes.yourdomain.com`)
   - `APP_PORT` - port to expose (default: 8080)

3. **Start the application**
   ```bash
   docker-compose up -d
   ```

4. **Configure Nginx Proxy Manager**
   - Add a new proxy host
   - Domain: `quotes.yourdomain.com`
   - Forward to: `your-server-ip:8080`
   - Enable SSL with Let's Encrypt

5. **First login**
   - Navigate to your subdomain
   - Register the first user (automatically becomes admin)
   - Go to Admin > Site Settings to customize branding

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `APP_PORT` | Exposed port for reverse proxy | `8080` |
| `FLASK_SECRET_KEY` | Session encryption key | Required |
| `POSTGRES_PASSWORD` | Database password | Required |
| `BASE_URL` | Your full URL (for emails) | `http://localhost` |
| `ALLOWED_EMAIL_DOMAIN` | Restrict registration | Empty (any) |
| `SENDER_EMAIL` | SMTP email for password reset | Empty (disabled) |
| `SENDER_PASSWORD` | SMTP password | - |
| `SMTP_SERVER` | SMTP server | `smtp.office365.com` |

### Architecture

```
┌─────────────────────────────────────────────────┐
│              Nginx Proxy Manager                │
│           (SSL/HTTPS termination)               │
└─────────────────────┬───────────────────────────┘
                      │ Port 8080
┌─────────────────────▼───────────────────────────┐
│              Docker Compose Stack               │
├─────────────────────────────────────────────────┤
│  Flask App  ◄──►  PostgreSQL  ◄──►  Redis      │
│  (Web)           (Database)      (Rate Limit)  │
└─────────────────────────────────────────────────┘
```

## Maintenance

### View logs
```bash
docker-compose logs -f web
```

### Backup database
```bash
docker-compose exec db pg_dump -U quoteapp quote_calculator > backup.sql
```

### Restore database
```bash
cat backup.sql | docker-compose exec -T db psql -U quoteapp quote_calculator
```

### Update application
```bash
git pull
docker-compose build
docker-compose up -d
```

### Restart services
```bash
docker-compose restart
```

## Color Schemes

Six built-in themes available in Admin > Site Settings:
- Professional Blue (default)
- Ocean Breeze
- Forest Green
- Sunset Glow
- Corporate Gray
- Midnight Purple

## License

MIT License
