#!/bin/bash

# Service Principal OAuth App Startup Script
# This script sets up and runs the Databricks SQL Interface with Service Principal authentication

set -e

echo "🤖 Starting Service Principal OAuth App"
echo "======================================"

# Check if config.env exists
if [ ! -f "config.env" ]; then
    echo "⚠️  config.env not found. Creating from example..."
    if [ -f "config.env.example" ]; then
        cp config.env.example config.env
        echo "📝 Please edit config.env with your Okta Service Application credentials:"
        echo "   - ISSUER_URL"
        echo "   - CLIENT_ID" 
        echo "   - CLIENT_SECRET"
        echo "   - DATABRICKS_SERVER_HOSTNAME"
        echo ""
        echo "💡 See OKTA-SERVICE-APP-SETUP.md for detailed setup instructions"
        exit 1
    else
        echo "❌ config.env.example not found!"
        exit 1
    fi
fi

# Load configuration from config.env
echo "📋 Loading configuration from config.env..."
export $(grep -v '^#' config.env | xargs)

# Validate required environment variables
echo "🔍 Validating configuration..."

if [ -z "$CLIENT_ID" ]; then
    echo "❌ CLIENT_ID not set in config.env"
    exit 1
fi

if [ -z "$CLIENT_SECRET" ]; then
    echo "❌ CLIENT_SECRET not set in config.env"
    exit 1
fi

if [ -z "$ISSUER_URL" ]; then
    echo "❌ ISSUER_URL not set in config.env"
    exit 1
fi

if [ -z "$DATABRICKS_SERVER_HOSTNAME" ]; then
    echo "❌ DATABRICKS_SERVER_HOSTNAME not set in config.env"
    exit 1
fi

# Set default port if not specified in config.env or environment
export PORT=${PORT:-7000}

echo "✅ Configuration validated"
echo "   Client ID: ${CLIENT_ID:0:12}..."
echo "   Databricks: $DATABRICKS_SERVER_HOSTNAME"
echo "   Port: $PORT"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔄 Activating virtual environment..."
source venv/bin/activate

# Install/upgrade dependencies
echo "📥 Installing dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt

echo ""
echo "🚀 Starting Service Principal OAuth App..."
echo "   URL: http://localhost:$PORT"
echo "   Type: Machine-to-Machine (M2M)"
echo "   Auth: OAuth Client Credentials"
echo ""
echo "📊 Access the SQL interface at: http://localhost:$PORT/sql"
echo "🏥 Health check available at: http://localhost:$PORT/health"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Start the application
python app.py
