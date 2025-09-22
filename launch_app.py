#!/usr/bin/env python3
"""
🛡️ AI-Powered Intrusion Detection System - Streamlit App Launcher
Simple Python launcher that works regardless of PATH issues
"""

import os
import sys
import subprocess
import time

def main():
    print("🛡️ AI-Powered Intrusion Detection System - Streamlit App")
    print("=" * 60)
    print("")
    
    # Check if models exist
    if not os.path.exists("models/quick_demo_model.pkl"):
        print("⚠️  Models not found. Training models first...")
        try:
            subprocess.run([sys.executable, "quick_demo.py"], check=True)
            print("✅ Models trained successfully!")
        except subprocess.CalledProcessError as e:
            print(f"❌ Error training models: {e}")
            return
        print("")
    
    print("🚀 Starting Streamlit App...")
    print("📱 The app will be available at: http://localhost:8501")
    print("🔄 Press Ctrl+C to stop the server")
    print("")
    
    # Start Streamlit
    try:
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", "streamlit_app.py",
            "--server.port", "8501", "--server.headless", "true"
        ])
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"❌ Error starting Streamlit: {e}")
        print("💡 Try running: python3 -m streamlit run streamlit_app.py --server.port 8501")

if __name__ == "__main__":
    main()
