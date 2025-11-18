#!/bin/bash

# External OAuth App Startup Script

echo "🚀 Starting External OAuth App for Databricks SQL..."

# Check if config.env exists
if [ ! -f "config.env" ]; then
    echo "❌ Error: config.env not found!"
    echo "📝 Please copy config.env.example to config.env and configure your OAuth settings."
    echo ""
    echo "   cp config.env.example config.env"
    echo "   # Edit config.env with your OAuth credentials"
    echo ""
    exit 1
fi

# Load environment variables
echo "📋 Loading configuration from config.env..."
source config.env

# Check required environment variables (SPA - no client secret needed)
required_vars=("ISSUER_URL" "CLIENT_ID")
missing_vars=()

for var in "${required_vars[@]}"; do
    if [ -z "${!var}" ]; then
        missing_vars+=("$var")
    fi
done

if [ ${#missing_vars[@]} -ne 0 ]; then
    echo "❌ Error: Missing required environment variables:"
    for var in "${missing_vars[@]}"; do
        echo "   - $var"
    done
    echo ""
    echo "📝 Please configure these variables in config.env"
    exit 1
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "🔧 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔌 Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "📦 Installing dependencies..."
pip install -r requirements.txt

# SPA apps don't need encryption keys for token storage

# Start the application
echo "🌐 Starting Flask application on port ${PORT:-5000}..."
echo "📱 Access the app at: http://localhost:${PORT:-5000}"
echo ""
echo "🔐 Security Features Enabled:"
echo "   ✅ PKCE OAuth flow (no client secrets)"
echo "   ✅ User authentication"
echo "   ✅ Secure session management"
echo "   ✅ Token exchange for Databricks"
echo ""
echo "Press Ctrl+C to stop the application"
echo "----------------------------------------"

python app.py
