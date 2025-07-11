#!/bin/bash

# Create deployment package for AWS

echo "Creating deployment package for AWS..."

# Clean up any existing deployment package
rm -f quote_calculator_v2_deployment.zip

# Create ZIP archive excluding development files
zip -r quote_calculator_v2_deployment.zip . \
    -x "venv/*" \
    -x "instance/*" \
    -x "*.pyc" \
    -x "__pycache__/*" \
    -x ".git/*" \
    -x ".env" \
    -x "*.log" \
    -x ".DS_Store" \
    -x "create_deployment_package.sh"

echo "✅ Deployment package created: quote_calculator_v2_deployment.zip"
echo "📋 To deploy:"
echo "   1. scp quote_calculator_v2_deployment.zip ubuntu@your-server:/home/ubuntu/"
echo "   2. ssh ubuntu@your-server"
echo "   3. unzip quote_calculator_v2_deployment.zip -d quote_calculator_v2"
echo "   4. cd quote_calculator_v2"
echo "   5. ./start.sh"
echo "   6. Follow DEPLOYMENT.md for complete setup"
echo ""
echo "📦 Package size: $(du -h quote_calculator_v2_deployment.zip | cut -f1)"
echo "🔐 Security: All security measures implemented and ready for production"
echo "⚠️  Don't forget to:"
echo "   - Change FLASK_SECRET_KEY in .env"
echo "   - Configure your domain in nginx"
echo "   - Set up SSL with Let's Encrypt"
echo "   - Enable CloudFlare protection"
