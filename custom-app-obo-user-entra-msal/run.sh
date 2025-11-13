#!/bin/bash

# Custom OAuth App - On Behalf Of User with Microsoft Entra ID (MSAL)
# Run script for local development

echo "🚀 Starting Databricks OAuth App with Microsoft Entra ID (MSAL)..."
echo "📍 Port: 9001"
echo "🔗 URL: http://localhost:9001"
echo "📚 Using: MSAL for Python"
echo ""

# Check if config.env exists
if [ ! -f "config.env" ]; then
    echo "❌ config.env file not found!"
    echo "📝 Please copy config.env.example to config.env and configure your settings:"
    echo "   cp config.env.example config.env"
    echo ""
    echo "🔧 Required configuration:"
    echo "   - ENTRA_TENANT_ID: Your Azure AD tenant ID"
    echo "   - ENTRA_CLIENT_ID: Your application client ID"
    echo "   - ENTRA_CLIENT_SECRET: Your application client secret (optional for SPAs)"
    echo ""
    exit 1
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔄 Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "📥 Installing dependencies (including MSAL)..."
pip install -r requirements.txt

# Start the application
echo ""
echo "✅ Starting Flask application with MSAL..."
echo "🌐 Open your browser to: http://localhost:9001"
echo "🛑 Press Ctrl+C to stop the server"
echo ""

python app.py

