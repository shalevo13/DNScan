#!/bin/bash
# Start the DNS Vulnerability Scanner Web Application

echo "🚀 Starting DNS Vulnerability Scanner..."
echo "=================================="

# Activate virtual environment
source venv/bin/activate

# Run the Flask application
echo "🌐 Server will be available at: http://localhost:5000"
echo "Press Ctrl+C to stop the server"
echo ""

python app.py
