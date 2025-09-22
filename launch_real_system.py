#!/usr/bin/env python3
"""
🛡️ AI-Powered Intrusion Detection System - Real ML System Launcher
Complete launcher that trains real models and starts the Streamlit app
"""

import os
import sys
import subprocess
import time
import argparse

def main():
    print("🛡️ AI-Powered Intrusion Detection System - Real ML System")
    print("=" * 70)
    print("")
    
    parser = argparse.ArgumentParser(description='Launch Real ML Intrusion Detection System')
    parser.add_argument('--skip-training', action='store_true', 
                       help='Skip model training and use existing models')
    parser.add_argument('--port', type=int, default=8501, 
                       help='Port for Streamlit app (default: 8501)')
    parser.add_argument('--train-only', action='store_true', 
                       help='Only train models, do not start app')
    
    args = parser.parse_args()
    
    # Check if models exist
    real_models_exist = (
        os.path.exists("models/ensemble_real_model.pkl") and
        os.path.exists("models/scaler_real.pkl") and
        os.path.exists("models/label_encoder_real.pkl")
    )
    
    demo_models_exist = (
        os.path.exists("models/quick_demo_model.pkl") and
        os.path.exists("models/quick_demo_scaler.pkl") and
        os.path.exists("models/quick_demo_label_encoder.pkl")
    )
    
    # Training phase
    if not args.skip_training:
        if not real_models_exist:
            print("🚀 Training real ML models...")
            print("   This will process 2.8M+ network flows and may take several minutes.")
            print("   The system will create advanced features and train ensemble models.")
            print("")
            
            try:
                # Train real models
                result = subprocess.run([sys.executable, "real_ml_system.py"], 
                                      capture_output=True, text=True)
                
                if result.returncode == 0:
                    print("✅ Real ML models trained successfully!")
                    print("")
                else:
                    print("❌ Error training real models:")
                    print(result.stderr)
                    print("")
                    print("🔄 Falling back to demo models...")
                    
                    # Fallback to demo models
                    if not demo_models_exist:
                        subprocess.run([sys.executable, "quick_demo.py"], check=True)
                        print("✅ Demo models created as fallback")
            except Exception as e:
                print(f"❌ Error during training: {e}")
                print("🔄 Falling back to demo models...")
                
                if not demo_models_exist:
                    try:
                        subprocess.run([sys.executable, "quick_demo.py"], check=True)
                        print("✅ Demo models created as fallback")
                    except:
                        print("❌ Could not create demo models either")
                        return
        else:
            print("✅ Real ML models already exist, skipping training")
            print("")
    else:
        print("⏭️ Skipping model training (--skip-training flag used)")
        print("")
    
    # Check what models are available
    if real_models_exist or os.path.exists("models/ensemble_real_model.pkl"):
        print("🎯 Using REAL ML models (trained on 2.8M+ flows)")
        model_type = "Real ML"
    elif demo_models_exist:
        print("🎯 Using DEMO models (trained on 50K flows)")
        model_type = "Demo"
    else:
        print("❌ No models found! Please train models first.")
        return
    
    print("")
    
    # Test the detector
    print("🔍 Testing the detection system...")
    try:
        result = subprocess.run([sys.executable, "real_time_detector.py"], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("✅ Detection system test passed!")
        else:
            print("⚠️ Detection system test had issues:")
            print(result.stderr)
    except subprocess.TimeoutExpired:
        print("⚠️ Detection system test timed out")
    except Exception as e:
        print(f"⚠️ Detection system test error: {e}")
    
    print("")
    
    # Start Streamlit app
    if not args.train_only:
        print("🚀 Starting Streamlit app...")
        print(f"📱 The app will be available at: http://localhost:{args.port}")
        print("🔄 Press Ctrl+C to stop the server")
        print("")
        print("🎮 App Features:")
        print("   • Real-time network flow analysis")
        print("   • Advanced ML model predictions")
        print("   • Interactive visualizations")
        print("   • System monitoring dashboard")
        print("   • Batch processing capabilities")
        print("")
        
        try:
            # Start Streamlit
            subprocess.run([
                sys.executable, "-m", "streamlit", "run", "streamlit_app.py",
                "--server.port", str(args.port), "--server.headless", "true"
            ])
        except KeyboardInterrupt:
            print("\n🛑 Server stopped by user")
        except Exception as e:
            print(f"❌ Error starting Streamlit: {e}")
            print("💡 Try running manually: python3 -m streamlit run streamlit_app.py --server.port 8501")
    else:
        print("✅ Model training completed. Use --train-only=false to start the app.")

if __name__ == "__main__":
    main()
