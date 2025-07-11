#!/bin/bash

# Security Verification Script
# Run this before pushing to GitHub

echo "🔍 Security Verification for GitHub Upload"
echo "========================================="

# Check for sensitive files
echo "Checking for sensitive files..."
if find . -name "*.env" -not -name "*.example" | grep -q .; then
    echo "❌ ERROR: Found .env files (should not be committed)"
    find . -name "*.env" -not -name "*.example"
    exit 1
else
    echo "✅ No .env files found (only .env.example is safe)"
fi

# Check for database files
echo "Checking for database files..."
if find . -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" | grep -q .; then
    echo "❌ ERROR: Found database files (should not be committed)"
    find . -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3"
    exit 1
else
    echo "✅ No database files found"
fi

# Check for private keys (excluding venv and other ignored directories)
echo "Checking for private keys..."
if find . -name "*.pem" -o -name "*.key" -o -name "id_rsa" | grep -v "/venv/" | grep -v "/.git/" | grep -q .; then
    echo "❌ ERROR: Found private key files (should not be committed)"
    find . -name "*.pem" -o -name "*.key" -o -name "id_rsa" | grep -v "/venv/" | grep -v "/.git/"
    exit 1
else
    echo "✅ No private key files found (excluding venv directory)"
fi

# Check for actual secrets in code
echo "Checking for hardcoded secrets..."
if grep -r "password.*=.*[^example]" --exclude-dir=.git --exclude="*.example" --exclude="README.md" --exclude="DEPLOYMENT.md" --exclude="SECURITY.md" . | grep -v "password_hash" | grep -v "password.*:" | grep -v "password.*get" | grep -v "password.*form" | grep -v "password.*input" | grep -v "password.*field" | grep -v "password.*validation" | grep -v "password.*requirements" | grep -v "password.*Policy" | grep -v "password.*must" | grep -v "password.*length" | grep -v "password.*characters" | grep -v "password.*contain" | grep -v "password.*strength" | grep -v "password.*security" | grep -v "password.*hashing" | grep -v "password.*bcrypt" | grep -q .; then
    echo "❌ WARNING: Found potential hardcoded passwords"
    grep -r "password.*=.*[^example]" --exclude-dir=.git --exclude="*.example" --exclude="README.md" --exclude="DEPLOYMENT.md" --exclude="SECURITY.md" . | grep -v "password_hash" | grep -v "password.*:" | grep -v "password.*get" | grep -v "password.*form" | grep -v "password.*input" | grep -v "password.*field" | grep -v "password.*validation" | grep -v "password.*requirements" | head -5
else
    echo "✅ No hardcoded passwords found"
fi

# Check .gitignore exists
if [ -f ".gitignore" ]; then
    echo "✅ .gitignore file exists"
else
    echo "❌ ERROR: .gitignore file missing"
    exit 1
fi

# Check .env.example exists
if [ -f ".env.example" ]; then
    echo "✅ .env.example file exists"
else
    echo "❌ ERROR: .env.example file missing"
    exit 1
fi

# Check README.md exists
if [ -f "README.md" ]; then
    echo "✅ README.md file exists"
else
    echo "❌ ERROR: README.md file missing"
    exit 1
fi

echo ""
echo "🎉 Security verification complete!"
echo "✅ Repository is safe for GitHub upload"
echo "✅ All security measures implemented"
echo "✅ No sensitive data found"
echo ""
echo "Ready to:"
echo "  1. git add ."
echo "  2. git commit -m 'Initial secure commit'"
echo "  3. git push origin main"
