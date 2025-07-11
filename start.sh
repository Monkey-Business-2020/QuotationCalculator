#!/bin/bash

# Quote Calculator Production Start Script

echo "Starting Quote Calculator Application..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install/upgrade dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "Creating .env file from example..."
    cp .env.example .env
    echo "⚠️  Please edit .env file with your production settings!"
    echo "⚠️  Change FLASK_SECRET_KEY to a secure random value!"
fi

# Run database migrations
echo "Initializing database..."
python3 -c "from app import app, db; app.app_context().push(); db.create_all(); print('Database initialized')"

# Start application with gunicorn
echo "Starting application with Gunicorn..."
gunicorn -w 4 -b 0.0.0.0:5001 app:app