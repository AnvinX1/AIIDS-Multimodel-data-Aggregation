#!/bin/bash

echo "🛡️ AI-Powered Intrusion Detection System - Streamlit App"
echo "========================================================"
echo ""

# Check if models exist
if [ ! -f "models/quick_demo_model.pkl" ]; then
    echo "⚠️  Models not found. Training models first..."
    python3 quick_demo.py
    echo ""
fi

echo "🚀 Starting Streamlit App..."
echo "📱 The app will be available at: http://localhost:8501"
echo "🔄 Press Ctrl+C to stop the server"
echo ""

# Start Streamlit using Python module (works even if streamlit command not in PATH)
python3 -m streamlit run streamlit_app.py --server.port 8501 --server.headless true
