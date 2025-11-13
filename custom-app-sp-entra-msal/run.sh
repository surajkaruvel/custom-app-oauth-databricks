#!/bin/bash

# Service Principal OAuth App with Microsoft Entra ID (MSAL)
# Run script for local development

echo "🚀 Starting Databricks Service Principal App with MSAL..."
echo "📍 Port: 9001"
echo "🔗 URL: http://localhost:9001"
echo "📚 Using: MSAL for Python (Client Credentials Flow)"
echo "🔧 Auth Type: Service Principal (Non-Interactive)"
echo ""

# Check if config.env exists
if [ ! -f "config.env" ]; then
    echo "❌ config.env file not found!"
    echo "📝 Please copy config.env.example to config.env and configure your settings:"
    echo "   cp config.env.example config.env"
    echo ""
    echo "🔧 Required configuration:"
    echo "   - SP_TENANT_ID: Your Azure AD tenant ID"
    echo "   - SP_CLIENT_ID: Your Service Principal (app) ID"
    echo "   - SP_CLIENT_SECRET: Your Service Principal secret"
    echo ""
    echo "💡 This is a Service Principal app - NO USER LOGIN required!"
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
echo "✅ Starting Flask application with MSAL (Service Principal)..."
echo "🌐 Open your browser to: http://localhost:9001"
echo "🔧 Authentication: Service Principal - NO USER INTERACTION REQUIRED"
echo "🛑 Press Ctrl+C to stop the server"
echo ""

python app.py

