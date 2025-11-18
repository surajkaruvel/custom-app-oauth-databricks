#!/bin/bash

# Databricks SQL Interface - Web Application Startup Script
# Session-Independent Refresh Tokens Demo

echo "🔄 Starting Databricks SQL Interface - Web Application"
echo "=================================================="
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python -m venv venv
    echo "✅ Virtual environment created"
    echo ""
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate
echo "✅ Virtual environment activated"
echo ""

# Install dependencies
echo "📥 Installing dependencies..."
pip install -r requirements.txt
echo "✅ Dependencies installed"
echo ""

# Check for config.env
if [ ! -f "config.env" ]; then
    echo "⚠️  config.env not found!"
    echo "📋 Copying config.env.example to config.env..."
    cp config.env.example config.env
    echo ""
    echo "🔧 Please edit config.env with your Okta Web Application credentials:"
    echo "   - CLIENT_ID (from Okta Web App)"
    echo "   - CLIENT_SECRET (from Okta Web App)"
    echo "   - ISSUER_URL (your Okta domain + auth server)"
    echo "   - DATABRICKS_SERVER_HOSTNAME"
    echo ""
    echo "💡 Then run this script again!"
    exit 1
fi

echo "✅ Configuration file found"
echo ""

# Load and validate configuration
source config.env

if [ -z "$CLIENT_ID" ] || [ -z "$CLIENT_SECRET" ] || [ -z "$ISSUER_URL" ]; then
    echo "❌ Missing required configuration in config.env:"
    echo "   - CLIENT_ID: ${CLIENT_ID:-'NOT SET'}"
    echo "   - CLIENT_SECRET: ${CLIENT_SECRET:-'NOT SET'}"
    echo "   - ISSUER_URL: ${ISSUER_URL:-'NOT SET'}"
    echo ""
    echo "🔧 Please edit config.env with your Okta Web Application credentials"
    exit 1
fi

echo "🎯 Configuration Summary:"
echo "   App Type: Web Application (Session-Independent Refresh Tokens)"
echo "   Port: ${PORT:-6000}"
echo "   Client ID: ${CLIENT_ID}"
echo "   Client Secret: ${CLIENT_SECRET:0:8}..."
echo "   Databricks: ${DATABRICKS_SERVER_HOSTNAME:-'Not configured'}"
echo ""

echo "🚀 Starting Web Application..."
echo "📱 Open your browser to: http://localhost:${PORT:-6000}"
echo ""
echo "🔄 Key Features:"
echo "   ✅ Session-independent refresh tokens"
echo "   ✅ Survives Okta web logout"
echo "   ✅ Up to 90-day sessions"
echo "   ✅ Automatic token refresh"
echo ""
echo "🆚 Compare with SPA version at: http://localhost:5000"
echo ""
echo "Press Ctrl+C to stop the server"
echo "=================================================="

# Start the Flask application
python app.py
