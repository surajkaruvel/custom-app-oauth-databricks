#!/bin/bash

# Databricks OAuth - On-Behalf-Of (OBO) Flow Runner
# Demonstrates middle-tier service exchanging user token for Databricks access

echo "=================================================="
echo "  Databricks OAuth - OBO Flow"
echo "=================================================="
echo ""
echo "Starting application..."
echo ""
echo "Configuration:"
echo "  - Port: 9001"
echo "  - URL: http://localhost:9001"
echo "  - Auth Type: On-Behalf-Of (OBO) Flow"
echo ""
echo "Architecture:"
echo "  1. User → Middle-Tier: Auth code flow"
echo "  2. Middle-Tier → Entra: OBO exchange"
echo "  3. Token works DIRECTLY with Databricks"
echo ""
echo "=================================================="
echo ""

# Check if config.env exists
if [ ! -f "config.env" ]; then
    echo "❌ ERROR: config.env not found!"
    echo "Please copy config.env.example to config.env and configure it."
    exit 1
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install/update dependencies
echo "📦 Installing dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt

# Run the application
echo ""
echo "🚀 Starting Flask application..."
echo "   Press Ctrl+C to stop"
echo ""
python app.py

