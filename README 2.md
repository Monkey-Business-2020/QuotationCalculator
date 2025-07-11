# iSTORM Quote Calculator v2

A modern, responsive web application for generating penetration testing quotes with user management and comprehensive reporting.

## 🚀 Features

### ✨ Modern UI/UX
- **Responsive Design**: Works perfectly on desktop, tablet, and mobile
- **Bootstrap 5**: Modern, clean interface with smooth animations
- **Interactive Elements**: Hover effects, tooltips, and smooth transitions
- **Dark/Light Theme**: Automatic theme detection and manual toggle

### 🔐 User Management
- **Secure Registration**: Restricted to @istormsolutions.co.uk email addresses
- **Individual User Accounts**: Each sales rep has their own credentials
- **Password Security**: Encrypted password storage with minimum requirements
- **Session Management**: Secure login/logout with Flask-Login

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
- **Authentication**: Flask-Login with secure password hashing
- **Deployment**: Docker + Docker Compose + Nginx
- **Security**: HTTPS ready, input validation, SQL injection protection

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

### 🌐 AWS Deployment

The application includes a comprehensive deployment script for AWS EC2 instances:

1. **Prepare EC2 Instance**:
   - Launch Ubuntu 22.04 LTS instance
   - Configure security groups (ports 22, 80, 443)
   - Set up SSH key access

2. **Deploy Application**:
   ```bash
   export DEPLOY_HOST=your-ec2-instance-ip
   ./deploy.sh
   ```

3. **Setup SSL Certificate**:
   ```bash
   ssh ubuntu@your-ec2-instance-ip
   sudo certbot --nginx
   ```

The deployment script automatically:
- ✅ Sets up Docker and dependencies
- ✅ Creates secure environment configuration
- ✅ Builds and starts the application
- ✅ Configures Nginx reverse proxy
- ✅ Sets up firewall rules
- ✅ Performs health checks

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

## 🔒 Security Features

- **Password Hashing**: Werkzeug security with salt
- **Session Management**: Secure Flask sessions
- **Input Validation**: Client and server-side validation
- **SQL Injection Protection**: SQLAlchemy ORM
- **XSS Protection**: Jinja2 template escaping
- **HTTPS Ready**: SSL certificate support
- **Domain Restriction**: Email-based access control

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
   - Verify password meets requirements (8+ characters)

2. **Calculation Errors**:
   - Ensure company name is entered
   - Check that at least one testing element is selected

3. **Database Issues**:
   - Check file permissions on `instance/` directory
   - Verify SQLite database file exists

4. **Deployment Issues**:
   - Check SSH connectivity to EC2 instance
   - Verify Docker is running: `sudo systemctl status docker`
   - Check application logs: `sudo docker-compose logs`

### Logs and Debugging

```bash
# View application logs
sudo docker-compose logs -f

# Check database
sqlite3 instance/quote_calculator_v2.db ".tables"

# Test application health
curl -f http://localhost:5000/login
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

### ✨ Enhanced Features
- **Modern UI**: Complete Bootstrap 5 redesign
- **User Management**: Individual accounts vs single shared login
- **Better Validation**: Real-time form validation and error handling
- **Detailed Reporting**: Category breakdowns and user attribution
- **Mobile Support**: Fully responsive design
- **Security**: Enhanced password security and input validation

### 🚀 Technical Improvements
- **Database Design**: Proper relational schema with foreign keys
- **Code Organization**: Modular design with separation of concerns
- **Deployment**: Professional Docker-based deployment
- **Error Handling**: Comprehensive error handling and user feedback
- **Performance**: Optimized database queries and caching

### 📊 Business Value
- **Team Visibility**: All sales reps can see team quotes
- **Detailed Analysis**: Category-wise day breakdowns for client discussions
- **Professional Appearance**: Modern, branded interface
- **Scalability**: Ready for team growth and feature expansion
- **Maintainability**: Clean code structure for easy updates

---

## 🎯 Getting Started Checklist

- [ ] Deploy to AWS EC2 instance
- [ ] Set up SSL certificate
- [ ] Configure domain name
- [ ] Create first admin user
- [ ] Test quote generation
- [ ] Train sales team
- [ ] Set up monitoring (optional)

Ready to generate professional penetration testing quotes! 🚀