"""
🛡️ Real-time Intrusion Detection System
Complete implementation with actual ML models and real-time processing
"""

import numpy as np
import pandas as pd
import joblib
import time
import threading
from datetime import datetime, timedelta
import json
import logging
from typing import Dict, List, Tuple, Optional
import warnings
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('real_ids_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class RealTimeDetector:
    """
    Real-time intrusion detection system using actual trained ML models
    """
    
    def __init__(self, model_path="models/"):
        self.model_path = model_path
        self.models = {}
        self.scaler = None
        self.label_encoder = None
        self.feature_selector = None
        self.feature_importance = {}
        self.training_history = {}
        self.detection_history = []
        self.alert_threshold = 0.8
        self.is_monitoring = False
        self.stats = {
            'total_detections': 0,
            'anomalies_detected': 0,
            'high_risk_alerts': 0,
            'start_time': None
        }
        
        # Load pre-trained models
        self.load_models()
        
    def load_models(self):
        """Load pre-trained real ML models and preprocessing objects"""
        try:
            # Try to load real models first
            if self._load_real_models():
                logger.info("✅ Real ML models loaded successfully")
                return
            
            # Fallback to demo models
            if self._load_demo_models():
                logger.info("✅ Demo models loaded successfully")
                return
            
            raise Exception("No models found")
            
        except Exception as e:
            logger.error(f"❌ Error loading models: {e}")
            raise
    
    def _load_real_models(self):
        """Load real trained models"""
        try:
            # Try robust models first
            self.scaler = joblib.load(f"{self.model_path}/scaler_robust.pkl")
            self.label_encoder = joblib.load(f"{self.model_path}/label_encoder_robust.pkl")
            self.feature_selector = joblib.load(f"{self.model_path}/feature_selector_robust.pkl")
            self.models['ensemble'] = joblib.load(f"{self.model_path}/ensemble_robust_model.pkl")
            
            if os.path.exists(f"{self.model_path}/training_history_robust.pkl"):
                self.training_history = joblib.load(f"{self.model_path}/training_history_robust.pkl")
            
            return True
        except:
            # Fallback to original real models
            try:
                self.scaler = joblib.load(f"{self.model_path}/scaler_real.pkl")
                self.label_encoder = joblib.load(f"{self.model_path}/label_encoder_real.pkl")
                self.feature_selector = joblib.load(f"{self.model_path}/feature_selector_real.pkl")
                self.models['ensemble'] = joblib.load(f"{self.model_path}/ensemble_real_model.pkl")
                
                if os.path.exists(f"{self.model_path}/feature_importance_real.pkl"):
                    self.feature_importance = joblib.load(f"{self.model_path}/feature_importance_real.pkl")
                
                if os.path.exists(f"{self.model_path}/training_history_real.pkl"):
                    self.training_history = joblib.load(f"{self.model_path}/training_history_real.pkl")
                
                return True
            except:
                return False
    
    def _load_demo_models(self):
        """Load demo models as fallback"""
        try:
            self.scaler = joblib.load(f"{self.model_path}/quick_demo_scaler.pkl")
            self.label_encoder = joblib.load(f"{self.model_path}/quick_demo_label_encoder.pkl")
            self.models['ensemble'] = joblib.load(f"{self.model_path}/quick_demo_model.pkl")
            # Don't load feature selector for demo models
            self.feature_selector = None
            return True
        except:
            return False
    
    def preprocess_flow(self, flow_data: Dict) -> np.ndarray:
        """
        Preprocess a single network flow for prediction using real feature engineering
        
        Args:
            flow_data: Dictionary containing flow features
            
        Returns:
            Preprocessed feature vector
        """
        try:
            # Convert to DataFrame for easier manipulation
            df = pd.DataFrame([flow_data])
            
            # Clean column names
            df.columns = df.columns.str.strip()
            
            # Remove label column if present
            if 'Label' in df.columns:
                df = df.drop('Label', axis=1)
            
            # Handle missing values
            df = df.fillna(0)
            
            # Handle infinite values
            df = df.replace([np.inf, -np.inf], 0)
            
            # Check if we have robust models (which expect advanced features)
            if hasattr(self.scaler, 'feature_names_in_') and 'robust' in str(type(self.scaler)):
                # Create advanced features for robust models
                df = self._create_real_advanced_features(df)
            else:
                # For demo models, use only basic features
                df = self._create_basic_features(df)
            
            # Scale features
            X_scaled = self.scaler.transform(df.values)
            
            # Select features if feature selector is available
            if self.feature_selector:
                X_selected = self.feature_selector.transform(X_scaled)
            else:
                X_selected = X_scaled
            
            return X_selected
            
        except Exception as e:
            logger.error(f"Error preprocessing flow: {e}")
            raise
    
    def _create_real_advanced_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Create real advanced features for a single flow"""
        try:
            # Packet ratio features
            if 'Total Fwd Packets' in df.columns and 'Total Backward Packets' in df.columns:
                df['Packet_Ratio'] = df['Total Fwd Packets'] / (df['Total Backward Packets'] + 1)
                df['Packet_Diff'] = df['Total Fwd Packets'] - df['Total Backward Packets']
                df['Packet_Asymmetry'] = abs(df['Packet_Ratio'] - 1)
            
            # Byte ratio features
            if 'Total Length of Fwd Packets' in df.columns and 'Total Length of Bwd Packets' in df.columns:
                df['Byte_Ratio'] = df['Total Length of Fwd Packets'] / (df['Total Length of Bwd Packets'] + 1)
                df['Byte_Diff'] = df['Total Length of Fwd Packets'] - df['Total Length of Bwd Packets']
                df['Byte_Asymmetry'] = abs(df['Byte_Ratio'] - 1)
            
            # Rate features
            if 'Flow Duration' in df.columns:
                if 'Total Fwd Packets' in df.columns:
                    df['Fwd_Packets_Per_Second'] = df['Total Fwd Packets'] / (df['Flow Duration'] + 1)
                if 'Total Backward Packets' in df.columns:
                    df['Bwd_Packets_Per_Second'] = df['Total Backward Packets'] / (df['Flow Duration'] + 1)
                if 'Total Length of Fwd Packets' in df.columns:
                    df['Fwd_Bytes_Per_Second'] = df['Total Length of Fwd Packets'] / (df['Flow Duration'] + 1)
                if 'Total Length of Bwd Packets' in df.columns:
                    df['Bwd_Bytes_Per_Second'] = df['Total Length of Bwd Packets'] / (df['Flow Duration'] + 1)
            
            # Flag combination features
            flag_columns = [col for col in df.columns if 'Flag' in col]
            if len(flag_columns) > 1:
                df['Total_Flags'] = df[flag_columns].sum(axis=1)
                df['Flag_Diversity'] = df[flag_columns].apply(lambda x: len(x[x > 0]), axis=1)
                df['Flag_Entropy'] = df[flag_columns].apply(lambda x: -np.sum(x * np.log(x + 1e-8)), axis=1)
            
            # Window size features
            if 'Init_Win_bytes_forward' in df.columns and 'Init_Win_bytes_backward' in df.columns:
                df['Win_Size_Ratio'] = df['Init_Win_bytes_forward'] / (df['Init_Win_bytes_backward'] + 1)
                df['Win_Size_Diff'] = df['Init_Win_bytes_forward'] - df['Init_Win_bytes_backward']
            
            # Protocol-specific features
            if 'Destination Port' in df.columns:
                df['Is_HTTP'] = df['Destination Port'].isin([80, 8080, 443, 8443]).astype(int)
                df['Is_SSH'] = (df['Destination Port'] == 22).astype(int)
                df['Is_DNS'] = (df['Destination Port'] == 53).astype(int)
                df['Is_FTP'] = df['Destination Port'].isin([21, 20]).astype(int)
                df['Is_SMTP'] = df['Destination Port'].isin([25, 587, 465]).astype(int)
                df['Is_Popular_Port'] = df['Destination Port'].isin([80, 443, 22, 21, 25, 53, 110, 143]).astype(int)
            
            # Statistical features
            numeric_cols = df.select_dtypes(include=[np.number]).columns
            if len(numeric_cols) > 0:
                df['Feature_Mean'] = df[numeric_cols].mean(axis=1)
                df['Feature_Std'] = df[numeric_cols].std(axis=1)
                df['Feature_Min'] = df[numeric_cols].min(axis=1)
                df['Feature_Max'] = df[numeric_cols].max(axis=1)
                df['Feature_Range'] = df['Feature_Max'] - df['Feature_Min']
                df['Feature_CV'] = df['Feature_Std'] / (df['Feature_Mean'] + 1e-8)
            
            return df
            
        except Exception as e:
            logger.error(f"Error creating advanced features: {e}")
            return df
    
    def _create_basic_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Create basic features for demo models"""
        try:
            # Just return the original features without advanced engineering
            return df
        except Exception as e:
            logger.error(f"Error creating basic features: {e}")
            return df
    
    def detect_anomaly(self, flow_data: Dict) -> Tuple[str, float, Dict]:
        """
        Detect if a network flow is anomalous using real ML models
        
        Args:
            flow_data: Dictionary containing flow features
            
        Returns:
            Tuple of (predicted_label, confidence, details)
        """
        try:
            # Preprocess the flow
            X_processed = self.preprocess_flow(flow_data)
            
            # Make prediction
            prediction = self.models['ensemble'].predict(X_processed)[0]
            probabilities = self.models['ensemble'].predict_proba(X_processed)[0]
            
            # Get predicted label
            predicted_label = self.label_encoder.inverse_transform([prediction])[0]
            
            # Get confidence (max probability)
            confidence = np.max(probabilities)
            
            # Create details dictionary
            details = {
                'timestamp': datetime.now().isoformat(),
                'predicted_label': predicted_label,
                'confidence': float(confidence),
                'all_probabilities': {
                    label: float(prob) for label, prob in 
                    zip(self.label_encoder.classes_, probabilities)
                },
                'is_anomaly': predicted_label != 'BENIGN',
                'risk_level': self._calculate_risk_level(confidence, predicted_label),
                'model_type': 'Real ML Model' if 'real' in str(type(self.models['ensemble'])) else 'Demo Model'
            }
            
            # Update statistics
            self.stats['total_detections'] += 1
            if details['is_anomaly']:
                self.stats['anomalies_detected'] += 1
            if details['risk_level'] in ['HIGH', 'CRITICAL']:
                self.stats['high_risk_alerts'] += 1
            
            # Log detection
            self._log_detection(details)
            
            return predicted_label, confidence, details
            
        except Exception as e:
            logger.error(f"Error in anomaly detection: {e}")
            return "ERROR", 0.0, {'error': str(e)}
    
    def _calculate_risk_level(self, confidence: float, label: str) -> str:
        """Calculate risk level based on confidence and label"""
        if label == 'BENIGN':
            return 'LOW'
        elif confidence >= 0.95:
            return 'CRITICAL'
        elif confidence >= 0.85:
            return 'HIGH'
        elif confidence >= 0.70:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _log_detection(self, details: Dict):
        """Log detection results"""
        self.detection_history.append(details)
        
        # Keep only last 1000 detections in memory
        if len(self.detection_history) > 1000:
            self.detection_history = self.detection_history[-1000:]
        
        # Log high-risk detections
        if details['risk_level'] in ['HIGH', 'CRITICAL']:
            logger.warning(f"🚨 HIGH-RISK DETECTION: {details['predicted_label']} "
                          f"(confidence: {details['confidence']:.3f}, risk: {details['risk_level']})")
    
    def batch_detect(self, flows: List[Dict]) -> List[Dict]:
        """
        Detect anomalies in a batch of network flows
        
        Args:
            flows: List of flow dictionaries
            
        Returns:
            List of detection results
        """
        results = []
        
        for i, flow in enumerate(flows):
            try:
                if i % 100 == 0:
                    logger.info(f"Processing flow {i+1}/{len(flows)}")
                
                label, confidence, details = self.detect_anomaly(flow)
                results.append(details)
            except Exception as e:
                logger.error(f"Error processing flow {i}: {e}")
                results.append({
                    'timestamp': datetime.now().isoformat(),
                    'error': str(e),
                    'predicted_label': 'ERROR',
                    'confidence': 0.0
                })
        
        return results
    
    def get_detection_stats(self) -> Dict:
        """Get comprehensive statistics about detections"""
        if not self.detection_history:
            return {
                'total_detections': 0,
                'anomalies_detected': 0,
                'anomaly_rate': 0.0,
                'high_risk_alerts': 0,
                'model_type': 'Unknown',
                'uptime': 'Unknown'
            }
        
        recent_detections = self.detection_history[-100:]  # Last 100 detections
        
        stats = {
            'total_detections': len(self.detection_history),
            'anomalies_detected': sum(1 for d in self.detection_history if d.get('is_anomaly', False)),
            'anomaly_rate': sum(1 for d in recent_detections if d.get('is_anomaly', False)) / len(recent_detections),
            'high_risk_alerts': sum(1 for d in self.detection_history if d.get('risk_level') in ['HIGH', 'CRITICAL']),
            'risk_distribution': {},
            'attack_types': {},
            'model_type': self.detection_history[0].get('model_type', 'Unknown') if self.detection_history else 'Unknown',
            'uptime': str(datetime.now() - self.stats['start_time']) if self.stats['start_time'] else 'Unknown'
        }
        
        # Calculate risk distribution
        for detection in recent_detections:
            risk_level = detection.get('risk_level', 'UNKNOWN')
            stats['risk_distribution'][risk_level] = stats['risk_distribution'].get(risk_level, 0) + 1
        
        # Calculate attack type distribution
        for detection in self.detection_history:
            if detection.get('is_anomaly', False):
                attack_type = detection.get('predicted_label', 'UNKNOWN')
                stats['attack_types'][attack_type] = stats['attack_types'].get(attack_type, 0) + 1
        
        return stats
    
    def start_monitoring(self, flow_source, interval: float = 1.0):
        """
        Start real-time monitoring of network flows
        
        Args:
            flow_source: Function that yields network flows
            interval: Monitoring interval in seconds
        """
        self.is_monitoring = True
        self.stats['start_time'] = datetime.now()
        logger.info("🚀 Starting real-time monitoring...")
        
        def monitor_loop():
            while self.is_monitoring:
                try:
                    # Get flows from source
                    flows = flow_source()
                    
                    if flows:
                        # Process flows
                        results = self.batch_detect(flows)
                        
                        # Log high-risk detections
                        for result in results:
                            if result.get('risk_level') in ['HIGH', 'CRITICAL']:
                                logger.warning(f"🚨 ALERT: {result['predicted_label']} "
                                             f"detected with confidence {result['confidence']:.3f}")
                    
                    time.sleep(interval)
                    
                except Exception as e:
                    logger.error(f"Error in monitoring loop: {e}")
                    time.sleep(interval)
        
        # Start monitoring in separate thread
        self.monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.is_monitoring = False
        logger.info("🛑 Stopped real-time monitoring")
    
    def export_detection_history(self, filename: str = None):
        """Export detection history to JSON file"""
        if filename is None:
            filename = f"real_detection_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.detection_history, f, indent=2)
            logger.info(f"📁 Detection history exported to {filename}")
        except Exception as e:
            logger.error(f"Error exporting detection history: {e}")
    
    def get_model_info(self) -> Dict:
        """Get information about the loaded models"""
        info = {
            'model_type': 'Real ML Model' if 'real' in str(type(self.models.get('ensemble', ''))) else 'Demo Model',
            'label_classes': self.label_encoder.classes_.tolist() if self.label_encoder else [],
            'feature_count': len(self.scaler.feature_names_in_) if hasattr(self.scaler, 'feature_names_in_') else 'Unknown',
            'training_history': self.training_history if self.training_history else {},
            'feature_importance_available': bool(self.feature_importance)
        }
        
        return info

# Example usage and testing
def create_realistic_flow(attack_type="BENIGN") -> Dict:
    """Create realistic network flows for testing"""
    if attack_type == "DDoS":
        # DDoS-like characteristics
        return {
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
        return {
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

def main():
    """Test the real-time detector"""
    print("🛡️ Real-time Intrusion Detection System")
    print("="*50)
    
    try:
        # Initialize detector
        detector = RealTimeDetector()
        
        # Get model info
        model_info = detector.get_model_info()
        print(f"📊 Model Type: {model_info['model_type']}")
        print(f"📊 Label Classes: {len(model_info['label_classes'])}")
        print(f"📊 Feature Count: {model_info['feature_count']}")
        
        # Test with realistic flows
        print("\n🔍 Testing with realistic flows...")
        
        # Test BENIGN flow
        benign_flow = create_realistic_flow("BENIGN")
        label, confidence, details = detector.detect_anomaly(benign_flow)
        risk_level = details.get('risk_level', 'UNKNOWN')
        print(f"✅ BENIGN Flow: {label} (confidence: {confidence:.3f}, risk: {risk_level})")
        
        # Test DDoS flow
        ddos_flow = create_realistic_flow("DDoS")
        label, confidence, details = detector.detect_anomaly(ddos_flow)
        risk_level = details.get('risk_level', 'UNKNOWN')
        print(f"🚨 DDoS Flow: {label} (confidence: {confidence:.3f}, risk: {risk_level})")
        
        # Get detection statistics
        stats = detector.get_detection_stats()
        print(f"\n📈 Detection Statistics:")
        print(f"   Total detections: {stats['total_detections']}")
        print(f"   Anomalies detected: {stats['anomalies_detected']}")
        print(f"   Anomaly rate: {stats['anomaly_rate']:.3f}")
        print(f"   High-risk alerts: {stats['high_risk_alerts']}")
        
        print("\n🎉 Real-time detector is ready for monitoring!")
        
    except Exception as e:
        print(f"❌ Error initializing detector: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()