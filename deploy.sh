#!/bin/bash

# AWS Deployment Script for iSTORM Quote Calculator
# This script will deploy the application to an AWS EC2 instance

set -e

echo "🚀 Starting deployment of iSTORM Quote Calculator..."

# Configuration
APP_NAME="quote-calculator-v2"
DEPLOY_USER="ubuntu"
DEPLOY_HOST="${DEPLOY_HOST:-your-ec2-instance-ip}"
DEPLOY_PATH="/opt/${APP_NAME}"
BACKUP_PATH="/opt/backups/${APP_NAME}"

# Check if required environment variables are set
if [ -z "$DEPLOY_HOST" ]; then
    echo "❌ Error: DEPLOY_HOST environment variable is not set"
    echo "Please set it with: export DEPLOY_HOST=your-ec2-instance-ip"
    exit 1
fi

# Function to run commands on remote server
run_remote() {
    ssh -o IdentitiesOnly=yes -o StrictHostKeyChecking=no ${DEPLOY_USER}@${DEPLOY_HOST} "$1"
}

# Function to copy files to remote server
copy_to_remote() {
    scp -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -r "$1" ${DEPLOY_USER}@${DEPLOY_HOST}:"$2"
}

echo "📋 Checking remote server connectivity..."
if ! run_remote "echo 'Connection successful'"; then
    echo "❌ Error: Cannot connect to remote server"
    exit 1
fi

echo "🔧 Setting up remote server environment..."
run_remote "
    sudo apt-get update
    sudo apt-get install -y docker.io docker-compose-plugin python3-pip nginx certbot python3-certbot-nginx
    sudo systemctl start docker
    sudo systemctl enable docker
    sudo usermod -aG docker ${DEPLOY_USER}
"

echo "📁 Creating application directories..."
run_remote "
    sudo mkdir -p ${DEPLOY_PATH}
    sudo mkdir -p ${BACKUP_PATH}
    sudo chown -R ${DEPLOY_USER}:${DEPLOY_USER} ${DEPLOY_PATH}
    sudo chown -R ${DEPLOY_USER}:${DEPLOY_USER} ${BACKUP_PATH}
"

echo "📦 Creating deployment package..."
tar -czf ${APP_NAME}.tar.gz \
    --exclude='.git' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='instance' \
    --exclude='node_modules' \
    .

echo "🚚 Copying application files to server..."
copy_to_remote "${APP_NAME}.tar.gz" "/tmp/"

echo "🔄 Backing up current deployment (if exists)..."
run_remote "
    if [ -d '${DEPLOY_PATH}/app' ]; then
        sudo cp -r ${DEPLOY_PATH} ${BACKUP_PATH}/backup-\$(date +%Y%m%d-%H%M%S)
        echo '✅ Backup created'
    else
        echo '📝 No existing deployment to backup'
    fi
"

echo "📂 Extracting application files..."
run_remote "
    cd ${DEPLOY_PATH}
    tar -xzf /tmp/${APP_NAME}.tar.gz
    rm /tmp/${APP_NAME}.tar.gz
"

echo "🔒 Setting up environment variables..."
run_remote "
    cd ${DEPLOY_PATH}
    if [ ! -f .env ]; then
        cp .env.example .env
        # Generate a secure secret key
        SECRET_KEY=\$(python3 -c 'import secrets; print(secrets.token_hex(32))')
        sed -i \"s/your-secret-key-here-change-this-in-production/\$SECRET_KEY/g\" .env
        echo '✅ Environment file created with secure secret key'
    else
        echo '📝 Environment file already exists'
    fi
"

echo "🐳 Building and starting Docker containers..."
run_remote "
    cd ${DEPLOY_PATH}
    sudo docker-compose down || true
    sudo docker-compose build
    sudo docker-compose up -d
"

echo "🏥 Waiting for application to start..."
sleep 30

echo "🔍 Checking application health..."
if run_remote "curl -f http://localhost:5000/login > /dev/null 2>&1"; then
    echo "✅ Application is running successfully!"
else
    echo "❌ Application health check failed"
    echo "🔍 Checking logs..."
    run_remote "cd ${DEPLOY_PATH} && sudo docker-compose logs"
    exit 1
fi

echo "🔥 Setting up firewall rules..."
run_remote "
    sudo ufw allow 22/tcp
    sudo ufw allow 80/tcp
    sudo ufw allow 443/tcp
    sudo ufw --force enable
"

echo "🎉 Deployment completed successfully!"
echo ""
echo "📊 Application Status:"
echo "   • URL: http://${DEPLOY_HOST}"
echo "   • Health Check: http://${DEPLOY_HOST}/health"
echo "   • Login: http://${DEPLOY_HOST}/login"
echo ""
echo "🔧 Useful commands:"
echo "   • Check logs: ssh ${DEPLOY_USER}@${DEPLOY_HOST} 'cd ${DEPLOY_PATH} && sudo docker-compose logs'"
echo "   • Restart app: ssh ${DEPLOY_USER}@${DEPLOY_HOST} 'cd ${DEPLOY_PATH} && sudo docker-compose restart'"
echo "   • Update app: ./deploy.sh"
echo ""
echo "🔐 Next steps:"
echo "   1. Set up SSL certificate with: ssh ${DEPLOY_USER}@${DEPLOY_HOST} 'sudo certbot --nginx'"
echo "   2. Configure your domain to point to ${DEPLOY_HOST}"
echo "   3. Create your first user account at http://${DEPLOY_HOST}/register"
echo ""

# Clean up local files
rm -f ${APP_NAME}.tar.gz

echo "✨ Deployment script completed!"
