# 🛡️ iSTORM Quote Calculator v2 - Enterprise Security Edition

A modern, secure web application for generating penetration testing quotes with comprehensive security features, user management, and OWASP Top 10 compliance.

## 🚀 Features

### ✨ Modern UI/UX
- **Responsive Design**: Works perfectly on desktop, tablet, and mobile
- **Bootstrap 5**: Modern, clean interface with smooth animations
- **Interactive Elements**: Hover effects, tooltips, and smooth transitions
- **Accessible Design**: WCAG compliant with proper ARIA labels

### 🔐 Enterprise Security
- **OWASP Top 10 Compliance**: Full compliance with security best practices
- **Rate Limiting**: 50 requests/minute global, endpoint-specific limits
- **Brute Force Protection**: Account lockout after 5 failed attempts (15-minute lockout)
- **IP-based Protection**: Temporary IP blocking after 10 failed attempts
- **Strong Password Policy**: 12+ characters with complexity requirements
- **Input Sanitization**: All user inputs cleaned and validated
- **CSRF Protection**: Token-based protection on all forms
- **Security Headers**: XSS, clickjacking, and content-type protection
- **Session Security**: Secure session management with 2-hour timeout
- **Username Enumeration Prevention**: Generic error messages
- **bcrypt Password Hashing**: Industry-standard password security

### 📊 Quote Generation
- **Comprehensive Testing Categories**:
  - Web Application Testing
  - External Infrastructure
  - Internal Infrastructure
  - API Assessment
  - Mobile Application Testing
  - Cloud Assessment
  - Kubernetes Security
  - Docker Security Review
  - Office 365 Audit

- **Smart Calculations**: Accurate day estimates based on scope parameters
- **Category Breakdown**: Detailed breakdown showing days per testing category
- **Client Name Validation**: Prevents quotes without client names
- **Form Validation**: Real-time validation with helpful error messages

### 📈 Reporting & History
- **Shared Quote History**: All sales reps can see quotes from all team members
- **Detailed Breakdown**: Shows testing days split by category (e.g., 5 days: 3 Web App, 2 Mobile)
- **User Attribution**: Displays which sales rep generated each quote
- **Timestamp Tracking**: Precise date and time for each quote
- **Export Ready**: Clean table format for easy data export

## 🛠️ Technical Stack

- **Backend**: Flask 3.0 with SQLAlchemy
- **Frontend**: Bootstrap 5 + Vanilla JavaScript
- **Database**: SQLite (production-ready with PostgreSQL support)
- **Authentication**: Flask-Login with bcrypt password hashing
- **Security**: Flask-Limiter, Flask-WTF, bleach, email-validator
- **Deployment**: Gunicorn + Nginx with SSL
- **Monitoring**: Login attempt tracking and security logging

## 📋 Requirements

- Python 3.11+
- Docker & Docker Compose (for deployment)
- Modern web browser

## 🚀 Quick Start

### Local Development

1. **Clone and Setup**:
   ```bash
   cd quote_calculator_v2
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Configure Environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your secret key
   ```

3. **Run Application**:
   ```bash
   python app.py
   ```

4. **Access Application**:
   - Open: http://localhost:5000
   - Register with an @istormsolutions.co.uk email
   - Start creating quotes!

### 🌐 AWS Deployment (Enterprise Security)

The application includes comprehensive deployment tools for secure AWS hosting:

#### Quick Deployment
1. **Create Deployment Package**:
   ```bash
   ./create_deployment_package.sh
   ```

2. **Upload to AWS**:
   ```bash
   scp quote_calculator_v2_deployment.zip ubuntu@your-server:/home/ubuntu/
   ```

3. **Deploy on Server**:
   ```bash
   ssh ubuntu@your-server
   unzip quote_calculator_v2_deployment.zip -d quote_calculator_v2
   cd quote_calculator_v2
   ./start.sh
   ```

#### Complete Security Setup
Follow the detailed `DEPLOYMENT.md` guide for:
- ✅ OWASP Top 10 security compliance
- ✅ Rate limiting and brute force protection
- ✅ SSL/TLS with Let's Encrypt
- ✅ Nginx security headers
- ✅ Fail2Ban intrusion prevention
- ✅ UFW firewall configuration
- ✅ CloudFlare integration guide
- ✅ System monitoring and logging

## 🔧 Configuration

### Environment Variables

```bash
FLASK_SECRET_KEY=your-secret-key-here
FLASK_ENV=production
DATABASE_URL=sqlite:///quote_calculator_v2.db
```

### Email Domain Restriction

The application restricts registration to `@istormsolutions.co.uk` email addresses. To change this:

1. Edit `app.py`
2. Modify the `validate_email_domain()` function
3. Update the registration form help text

## 📊 Database Schema

### Users Table
- `id`: Primary key
- `username`: Unique username
- `email`: Email address (domain restricted)
- `password_hash`: Encrypted password
- `full_name`: Display name
- `created_at`: Registration timestamp

### Quotes Table
- `id`: Primary key
- `user_id`: Foreign key to Users
- `company_name`: Client company name
- `selected_elements`: JSON array of selected testing types
- `form_data`: JSON object with detailed parameters
- `estimated_days`: Total calculated days
- `category_breakdown`: JSON object with days per category
- `created_at`: Quote generation timestamp

## 🔒 Security Features (OWASP Top 10 Compliant)

### 🛡️ Authentication & Authorization
- **bcrypt Password Hashing**: Industry-standard password security
- **Strong Password Policy**: 12+ characters, complexity requirements
- **Account Lockout**: 5 failed attempts = 15-minute lockout
- **Session Security**: 2-hour timeout, secure cookie settings
- **Domain Restriction**: Email-based access control (@istormsolutions.co.uk)

### 🚫 Attack Prevention
- **Rate Limiting**: Global and endpoint-specific limits
- **Brute Force Protection**: IP-based blocking after 10 failed attempts
- **CSRF Protection**: Token-based protection on all forms
- **Input Sanitization**: All user inputs cleaned with bleach
- **SQL Injection Protection**: Parameterized queries with SQLAlchemy
- **XSS Protection**: Template escaping and security headers

### 🔐 Network Security
- **Security Headers**: X-Frame-Options, X-Content-Type-Options, CSP
- **SSL/TLS Ready**: HTTPS with strong cipher suites
- **Nginx Security**: Rate limiting, request filtering
- **Firewall Integration**: UFW and fail2ban support

### 📊 Security Monitoring
- **Login Attempt Tracking**: All login attempts logged
- **Failed Login Monitoring**: Track and alert on suspicious activity
- **User Activity Logging**: Comprehensive audit trail
- **Security Event Tracking**: Failed authentications and rate limit violations

## 🎨 Customization

### Adding New Testing Categories

1. **Backend** (`app.py`):
   - Add calculation logic to `calculate_category_breakdown()`
   - Add new route handlers if needed

2. **Frontend** (`dashboard.html`):
   - Add new element card in the main section
   - Create corresponding questions panel
   - Update JavaScript event handlers

3. **Database**:
   - No schema changes required (uses JSON fields)

### Modifying Calculations

Edit the calculation logic in `app.py` in the `calculate_category_breakdown()` function. Each category has its own calculation rules based on the form parameters.

## 📱 Mobile Support

The application is fully responsive and works perfectly on:
- 📱 Mobile phones (iOS/Android)
- 📱 Tablets
- 💻 Desktop computers
- 🖥️ Large screens

## 🔄 Backup & Recovery

### Database Backup
```bash
# Create backup
cp instance/quote_calculator_v2.db backup_$(date +%Y%m%d).db

# Restore backup
cp backup_20240101.db instance/quote_calculator_v2.db
```

### Full Application Backup
The deployment script automatically creates backups before each deployment in `/opt/backups/`.

## 🆘 Troubleshooting

### Common Issues

1. **Registration Fails**:
   - Check email domain (@istormsolutions.co.uk required)
   - Verify password meets requirements (12+ characters with complexity)
   - Check for account lockout due to failed attempts

2. **Login Issues**:
   - Account may be locked after 5 failed attempts (15-minute lockout)
   - Check for IP blocking due to excessive failed attempts
   - Verify username/password combination

3. **Rate Limiting**:
   - Application enforces 50 requests/minute globally
   - Login attempts limited to 10/minute
   - Registration attempts limited to 5/minute

4. **Security Events**:
   - Check login attempt logs for suspicious activity
   - Review security headers in browser developer tools
   - Monitor failed authentication attempts

### Logs and Debugging

```bash
# View application logs
sudo journalctl -u quote_calculator -f

# Check security logs
grep "failed login" /var/log/auth.log

# Test application health
curl -f http://localhost:5001/login

# Check rate limiting
curl -I http://localhost:5001/login
```

### Security Monitoring

```bash
# Check failed login attempts
sudo grep "Invalid credentials" /var/log/syslog

# Monitor rate limiting
sudo grep "Rate limit exceeded" /var/log/nginx/error.log

# Check account lockouts
sudo grep "Account locked" /var/log/syslog
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes following the existing code style
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is proprietary to iSTORM Solutions. All rights reserved.

## 🏆 Improvements Over Original

### 🛡️ Security Enhancements
- **OWASP Top 10 Compliance**: Full security audit and implementation
- **Enterprise Security**: Rate limiting, brute force protection, account lockout
- **Input Validation**: Comprehensive sanitization and validation
- **Authentication**: bcrypt hashing, strong password policies
- **Session Security**: Secure session management with timeouts
- **Network Security**: Security headers, CSRF protection, SSL/TLS

### ✨ Enhanced Features
- **Modern UI**: Complete Bootstrap 5 redesign with accessibility
- **User Management**: Individual accounts with proper authorization
- **Better Validation**: Real-time form validation and error handling
- **Detailed Reporting**: Category breakdowns and user attribution
- **Mobile Support**: Fully responsive design
- **Security Monitoring**: Login attempt tracking and audit trails

### 🚀 Technical Improvements
- **Database Design**: Proper relational schema with foreign keys
- **Code Organization**: Modular design with separation of concerns
- **Deployment**: Professional production-ready deployment
- **Error Handling**: Comprehensive error handling and user feedback
- **Performance**: Optimized database queries and security measures

### 📊 Business Value
- **Security Compliance**: Ready for public internet hosting
- **Team Visibility**: All sales reps can see team quotes
- **Detailed Analysis**: Category-wise day breakdowns for client discussions
- **Professional Appearance**: Modern, branded interface
- **Scalability**: Ready for team growth and feature expansion
- **Maintainability**: Clean code structure for easy updates

---

## ⚠️ Security Notice

This application implements enterprise-grade security measures and is suitable for public internet hosting. Key security features include:

- **No Sensitive Data in Repository**: All secrets, keys, and passwords are externalized
- **Production-Ready**: Follows security best practices for production deployment
- **OWASP Compliant**: Addresses all OWASP Top 10 security risks
- **CloudFlare Ready**: Designed to work with CloudFlare for additional protection
- **Audit Trail**: Comprehensive logging of all security events

## 🎯 Getting Started Checklist

- [ ] Clone repository and review security documentation
- [ ] Create deployment package with `./create_deployment_package.sh`
- [ ] Deploy to AWS EC2 instance following `DEPLOYMENT.md`
- [ ] Set up SSL certificate with Let's Encrypt
- [ ] Configure domain name and CloudFlare protection
- [ ] Create first admin user with strong password
- [ ] Test all security features (rate limiting, lockout, etc.)
- [ ] Set up monitoring and alerting
- [ ] Train sales team on secure usage

**🔒 This application is ready for enterprise deployment with comprehensive security measures!**