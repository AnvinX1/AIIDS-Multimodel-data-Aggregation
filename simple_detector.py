"""
Simple Real-time Intrusion Detection Demo
Works with the quick demo model
"""

import numpy as np
import pandas as pd
import joblib
from datetime import datetime
import json

class SimpleDetector:
    """Simple intrusion detector for demonstration"""
    
    def __init__(self, model_path="models/"):
        self.model_path = model_path
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.detection_history = []
        
        # Load models
        self.load_models()
    
    def load_models(self):
        """Load pre-trained models"""
        try:
            self.model = joblib.load(f"{self.model_path}/quick_demo_model.pkl")
            self.scaler = joblib.load(f"{self.model_path}/quick_demo_scaler.pkl")
            self.label_encoder = joblib.load(f"{self.model_path}/quick_demo_label_encoder.pkl")
            print("✅ Models loaded successfully!")
        except Exception as e:
            print(f"❌ Error loading models: {e}")
            print("💡 Run quick_demo.py first to train models")
    
    def create_sample_flow(self, attack_type="BENIGN"):
        """Create a sample network flow for testing"""
        if attack_type == "DDoS":
            # DDoS-like characteristics
            flow = {
                'Destination Port': 80,
                'Flow Duration': 100,  # Short duration
                'Total Fwd Packets': 1000,  # High packet count
                'Total Backward Packets': 0,  # No response
                'Total Length of Fwd Packets': 100000,
                'Total Length of Bwd Packets': 0,
                'Fwd Packet Length Max': 100,
                'Fwd Packet Length Min': 100,
                'Fwd Packet Length Mean': 100,
                'Fwd Packet Length Std': 0,
                'Bwd Packet Length Max': 0,
                'Bwd Packet Length Min': 0,
                'Bwd Packet Length Mean': 0,
                'Bwd Packet Length Std': 0,
                'Flow Bytes/s': 1000000,
                'Flow Packets/s': 10000,
                'Flow IAT Mean': 0.1,
                'Flow IAT Std': 0.01,
                'Flow IAT Max': 0.2,
                'Flow IAT Min': 0.05,
                'Fwd IAT Total': 100,
                'Fwd IAT Mean': 0.1,
                'Fwd IAT Std': 0.01,
                'Fwd IAT Max': 0.2,
                'Fwd IAT Min': 0.05,
                'Bwd IAT Total': 0,
                'Bwd IAT Mean': 0,
                'Bwd IAT Std': 0,
                'Bwd IAT Max': 0,
                'Bwd IAT Min': 0,
                'Fwd PSH Flags': 0,
                'Bwd PSH Flags': 0,
                'Fwd URG Flags': 0,
                'Bwd URG Flags': 0,
                'Fwd Header Length': 40,
                'Bwd Header Length': 0,
                'Fwd Packets/s': 10000,
                'Bwd Packets/s': 0,
                'Min Packet Length': 100,
                'Max Packet Length': 100,
                'Packet Length Mean': 100,
                'Packet Length Std': 0,
                'Packet Length Variance': 0,
                'FIN Flag Count': 0,
                'SYN Flag Count': 1000,
                'RST Flag Count': 0,
                'PSH Flag Count': 0,
                'ACK Flag Count': 0,
                'URG Flag Count': 0,
                'CWE Flag Count': 0,
                'ECE Flag Count': 0,
                'Down/Up Ratio': 0,
                'Average Packet Size': 100,
                'Avg Fwd Segment Size': 100,
                'Avg Bwd Segment Size': 0,
                'Fwd Header Length.1': 40,
                'Fwd Avg Bytes/Bulk': 0,
                'Fwd Avg Packets/Bulk': 0,
                'Fwd Avg Bulk Rate': 0,
                'Bwd Avg Bytes/Bulk': 0,
                'Bwd Avg Packets/Bulk': 0,
                'Bwd Avg Bulk Rate': 0,
                'Subflow Fwd Packets': 1000,
                'Subflow Fwd Bytes': 100000,
                'Subflow Bwd Packets': 0,
                'Subflow Bwd Bytes': 0,
                'Init_Win_bytes_forward': 65535,
                'Init_Win_bytes_backward': 0,
                'act_data_pkt_fwd': 0,
                'min_seg_size_forward': 20,
                'Active Mean': 50,
                'Active Std': 10,
                'Active Max': 100,
                'Active Min': 10,
                'Idle Mean': 0,
                'Idle Std': 0,
                'Idle Max': 0,
                'Idle Min': 0
            }
        else:
            # BENIGN flow characteristics
            flow = {
                'Destination Port': 80,
                'Flow Duration': 1000,
                'Total Fwd Packets': 10,
                'Total Backward Packets': 8,
                'Total Length of Fwd Packets': 1200,
                'Total Length of Bwd Packets': 800,
                'Fwd Packet Length Max': 150,
                'Fwd Packet Length Min': 100,
                'Fwd Packet Length Mean': 120,
                'Fwd Packet Length Std': 15,
                'Bwd Packet Length Max': 120,
                'Bwd Packet Length Min': 80,
                'Bwd Packet Length Mean': 100,
                'Bwd Packet Length Std': 12,
                'Flow Bytes/s': 2000,
                'Flow Packets/s': 18,
                'Flow IAT Mean': 55,
                'Flow IAT Std': 10,
                'Flow IAT Max': 100,
                'Flow IAT Min': 20,
                'Fwd IAT Total': 900,
                'Fwd IAT Mean': 90,
                'Fwd IAT Std': 20,
                'Fwd IAT Max': 150,
                'Fwd IAT Min': 30,
                'Bwd IAT Total': 800,
                'Bwd IAT Mean': 100,
                'Bwd IAT Std': 15,
                'Bwd IAT Max': 120,
                'Bwd IAT Min': 50,
                'Fwd PSH Flags': 0,
                'Bwd PSH Flags': 0,
                'Fwd URG Flags': 0,
                'Bwd URG Flags': 0,
                'Fwd Header Length': 40,
                'Bwd Header Length': 40,
                'Fwd Packets/s': 10,
                'Bwd Packets/s': 8,
                'Min Packet Length': 80,
                'Max Packet Length': 150,
                'Packet Length Mean': 110,
                'Packet Length Std': 20,
                'Packet Length Variance': 400,
                'FIN Flag Count': 0,
                'SYN Flag Count': 1,
                'RST Flag Count': 0,
                'PSH Flag Count': 0,
                'ACK Flag Count': 1,
                'URG Flag Count': 0,
                'CWE Flag Count': 0,
                'ECE Flag Count': 0,
                'Down/Up Ratio': 0.8,
                'Average Packet Size': 110,
                'Avg Fwd Segment Size': 120,
                'Avg Bwd Segment Size': 100,
                'Fwd Header Length.1': 40,
                'Fwd Avg Bytes/Bulk': 0,
                'Fwd Avg Packets/Bulk': 0,
                'Fwd Avg Bulk Rate': 0,
                'Bwd Avg Bytes/Bulk': 0,
                'Bwd Avg Packets/Bulk': 0,
                'Bwd Avg Bulk Rate': 0,
                'Subflow Fwd Packets': 10,
                'Subflow Fwd Bytes': 1200,
                'Subflow Bwd Packets': 8,
                'Subflow Bwd Bytes': 800,
                'Init_Win_bytes_forward': 65535,
                'Init_Win_bytes_backward': 65535,
                'act_data_pkt_fwd': 0,
                'min_seg_size_forward': 20,
                'Active Mean': 500,
                'Active Std': 100,
                'Active Max': 800,
                'Active Min': 200,
                'Idle Mean': 300,
                'Idle Std': 50,
                'Idle Max': 400,
                'Idle Min': 200
            }
        
        return flow
    
    def detect_anomaly(self, flow_data):
        """Detect if a network flow is anomalous"""
        try:
            # Convert to DataFrame
            df = pd.DataFrame([flow_data])
            df.columns = df.columns.str.strip()
            
            # Handle missing values
            df = df.fillna(0)
            df = df.replace([np.inf, -np.inf], 0)
            
            # Scale features
            X_scaled = self.scaler.transform(df.values)
            
            # Make prediction
            prediction = self.model.predict(X_scaled)[0]
            probabilities = self.model.predict_proba(X_scaled)[0]
            
            # Get predicted label
            predicted_label = self.label_encoder.inverse_transform([prediction])[0]
            confidence = np.max(probabilities)
            
            # Create result
            result = {
                'timestamp': datetime.now().isoformat(),
                'predicted_label': predicted_label,
                'confidence': float(confidence),
                'is_anomaly': predicted_label != 'BENIGN',
                'risk_level': self._calculate_risk_level(confidence, predicted_label),
                'all_probabilities': {
                    label: float(prob) for label, prob in 
                    zip(self.label_encoder.classes_, probabilities)
                }
            }
            
            # Store in history
            self.detection_history.append(result)
            if len(self.detection_history) > 100:
                self.detection_history = self.detection_history[-100:]
            
            return result
            
        except Exception as e:
            return {
                'timestamp': datetime.now().isoformat(),
                'error': str(e),
                'predicted_label': 'ERROR',
                'confidence': 0.0,
                'is_anomaly': False,
                'risk_level': 'UNKNOWN'
            }
    
    def _calculate_risk_level(self, confidence, label):
        """Calculate risk level"""
        if label == 'BENIGN':
            return 'LOW'
        elif confidence >= 0.9:
            return 'CRITICAL'
        elif confidence >= 0.7:
            return 'HIGH'
        elif confidence >= 0.5:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def demo_detection(self):
        """Run a demonstration of the detection system"""
        print("🛡️ AI-Powered Intrusion Detection System - Demo")
        print("="*60)
        
        if self.model is None:
            print("❌ Models not loaded. Run quick_demo.py first.")
            return
        
        print("🔍 Testing with sample network flows...\n")
        
        # Test with BENIGN flow
        print("1️⃣ Testing BENIGN flow:")
        benign_flow = self.create_sample_flow("BENIGN")
        result = self.detect_anomaly(benign_flow)
        print(f"   Predicted: {result['predicted_label']}")
        print(f"   Confidence: {result['confidence']:.4f} ({result['confidence']*100:.2f}%)")
        print(f"   Risk Level: {result['risk_level']}")
        print(f"   Is Anomaly: {result['is_anomaly']}\n")
        
        # Test with DDoS flow
        print("2️⃣ Testing DDoS flow:")
        ddos_flow = self.create_sample_flow("DDoS")
        result = self.detect_anomaly(ddos_flow)
        print(f"   Predicted: {result['predicted_label']}")
        print(f"   Confidence: {result['confidence']:.4f} ({result['confidence']*100:.2f}%)")
        print(f"   Risk Level: {result['risk_level']}")
        print(f"   Is Anomaly: {result['is_anomaly']}\n")
        
        # Show detection statistics
        print("📊 Detection Statistics:")
        total_detections = len(self.detection_history)
        anomalies = sum(1 for d in self.detection_history if d.get('is_anomaly', False))
        print(f"   Total Detections: {total_detections}")
        print(f"   Anomalies Detected: {anomalies}")
        print(f"   Anomaly Rate: {anomalies/total_detections*100:.1f}%" if total_detections > 0 else "   Anomaly Rate: 0%")
        
        print(f"\n🎉 Demo completed successfully!")
        print(f"💡 The system can now detect network intrusions in real-time!")

def main():
    """Main function"""
    detector = SimpleDetector()
    detector.demo_detection()

if __name__ == "__main__":
    main()
