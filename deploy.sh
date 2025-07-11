#\!/bin/bash

# Production deployment script for Quote Calculator
# Run this script on your Ubuntu server

echo "🚀 Starting Quote Calculator deployment..."

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "❌ This script should not be run as root"
   exit 1
fi

# Update system packages
echo "📦 Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install required packages
echo "🔧 Installing required packages..."
sudo apt install -y nginx python3-pip python3-venv python3-dev build-essential libssl-dev libffi-dev python3-setuptools certbot python3-certbot-nginx

# Create application directory
APP_DIR="/home/ubuntu/quote_calculator_v2"
echo "📁 Creating application directory at $APP_DIR..."
sudo mkdir -p $APP_DIR
sudo chown ubuntu:ubuntu $APP_DIR

# Copy application files (assuming you've uploaded them)
echo "📋 Copying application files..."
# Note: You'll need to upload your files to the server first
# rsync -av --exclude='.git' --exclude='venv' --exclude='__pycache__' . $APP_DIR/

# Set up virtual environment
echo "🐍 Setting up Python virtual environment..."
cd $APP_DIR
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo "📚 Installing Python dependencies..."
pip install --upgrade pip
pip install gunicorn flask flask-login werkzeug flask-sqlalchemy flask-limiter flask-wtf bcrypt python-dotenv email-validator bleach

# Create .env file
echo "⚙️ Creating .env file..."
cat > .env << ENVEOF
FLASK_SECRET_KEY=$(openssl rand -hex 32)
FLASK_DEBUG=False
FLASK_ENV=production
ENVEOF

# Initialize database
echo "🗄️ Initializing database..."
python3 -c "from app import app, db; app.app_context().push(); db.create_all(); print('Database initialized')"

# Install systemd service
echo "🔄 Installing systemd service..."
sudo cp quote-calculator.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable quote-calculator
sudo systemctl start quote-calculator

# Configure nginx
echo "🌐 Configuring nginx..."
sudo cp nginx-site.conf /etc/nginx/sites-available/calc.istormsolutions.online
sudo ln -sf /etc/nginx/sites-available/calc.istormsolutions.online /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

# Test nginx configuration
echo "🧪 Testing nginx configuration..."
sudo nginx -t

if [ $? -eq 0 ]; then
    echo "✅ Nginx configuration is valid"
    sudo systemctl restart nginx
    sudo systemctl enable nginx
else
    echo "❌ Nginx configuration has errors"
    exit 1
fi

# Configure firewall
echo "🔒 Configuring firewall..."
sudo ufw allow 'Nginx Full'
sudo ufw allow ssh
sudo ufw --force enable

# CloudFlare SSL setup instructions
echo "🔐 CloudFlare SSL setup required..."
echo "⚠️  Please follow the CloudFlare SSL setup guide in cloudflare-ssl-setup.md"
echo "⚠️  You need to:"
echo "   1. Generate CloudFlare Origin Certificate"
echo "   2. Save certificate files to /etc/ssl/certs/ and /etc/ssl/private/"
echo "   3. Set CloudFlare SSL mode to 'Full (strict)'"
echo "   4. Configure DNS with CloudFlare proxy enabled"

# Final status check
echo "🏁 Checking service status..."
sudo systemctl status quote-calculator --no-pager -l
sudo systemctl status nginx --no-pager -l

echo "🎉 Deployment complete\!"
echo "📍 Your application should be accessible at: https://calc.istormsolutions.online"
echo "🔍 Check logs with: sudo journalctl -u quote-calculator -f"
echo "🔧 Restart service with: sudo systemctl restart quote-calculator"
EOF < /dev/null