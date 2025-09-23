"""
🛡️ Robust AI-Powered Intrusion Detection System
Simplified version that works reliably with the large dataset
"""

import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder, RobustScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.utils.class_weight import compute_class_weight
from sklearn.feature_selection import SelectKBest, f_classif
import xgboost as xgb
import lightgbm as lgb
import joblib
import warnings
warnings.filterwarnings('ignore')

class RobustMLIDS:
    """
    Robust AI-Powered Intrusion Detection System
    Simplified but reliable implementation
    """
    
    def __init__(self, data_path=".", model_save_path="models/"):
        self.data_path = data_path
        self.model_save_path = model_save_path
        self.scaler = RobustScaler()  # More robust to outliers
        self.label_encoder = LabelEncoder()
        self.feature_selector = None
        self.models = {}
        self.training_history = {}
        
        # Create model directory
        os.makedirs(model_save_path, exist_ok=True)
        
    def load_robust_data(self, sample_size=100000):
        """Load and process network flow data with sampling for efficiency"""
        print("🔄 Loading network flow data (sampled for efficiency)...")
        
        csv_files = [
            "MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
            "MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", 
            "MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv",
            "MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv",
            "MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
            "MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
            "MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv",
            "MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv"
        ]
        
        dataframes = []
        total_loaded = 0
        
        for file in csv_files:
            if os.path.exists(file):
                print(f"📊 Loading {file}...")
                df = pd.read_csv(file)
                df.columns = df.columns.str.strip()
                
                # Sample from each file to keep it manageable
                if len(df) > sample_size // len(csv_files):
                    df = df.sample(n=sample_size // len(csv_files), random_state=42)
                
                dataframes.append(df)
                total_loaded += len(df)
                print(f"   ✅ Loaded: {len(df)} flows")
        
        if dataframes:
            self.network_data = pd.concat(dataframes, ignore_index=True)
            print(f"🎯 Combined dataset: {self.network_data.shape[0]} flows, {self.network_data.shape[1]} features")
            
            # Show label distribution
            label_counts = self.network_data['Label'].value_counts()
            print(f"📈 Attack type distribution:")
            for label, count in label_counts.head(10).items():
                percentage = (count / len(self.network_data)) * 100
                print(f"   {label}: {count:,} ({percentage:.1f}%)")
            
            return self.network_data
        else:
            raise FileNotFoundError("❌ No network data files found!")
    
    def preprocess_robust_data(self):
        """Preprocess network data with robust handling"""
        print("🔧 Preprocessing network data...")
        
        # Clean data
        print("   🧹 Cleaning data...")
        self.network_data = self.network_data.dropna()
        print(f"   ✅ After cleaning: {self.network_data.shape}")
        
        # Filter out classes with too few samples
        print("   🔍 Filtering classes with insufficient samples...")
        label_counts = self.network_data['Label'].value_counts()
        min_samples = 10  # Minimum samples per class
        valid_labels = label_counts[label_counts >= min_samples].index
        self.network_data = self.network_data[self.network_data['Label'].isin(valid_labels)]
        print(f"   ✅ After filtering: {self.network_data.shape}")
        print(f"   📊 Valid classes: {len(valid_labels)}")
        
        # Separate features and labels
        feature_columns = [col for col in self.network_data.columns if col != 'Label']
        X = self.network_data[feature_columns]
        y = self.network_data['Label']
        
        # Robust data cleaning
        print("   🔄 Robust data cleaning...")
        X = self._robust_clean_data(X)
        
        # Create simple advanced features
        print("   🚀 Creating advanced features...")
        X_advanced = self._create_simple_advanced_features(X, feature_columns)
        
        # Encode labels
        print("   🏷️ Encoding labels...")
        y_encoded = self.label_encoder.fit_transform(y)
        
        # Scale features with robust scaler
        print("   📏 Scaling features...")
        X_scaled = self.scaler.fit_transform(X_advanced)
        
        print(f"✅ Preprocessed data: {X_scaled.shape}")
        print(f"✅ Labels: {len(np.unique(y_encoded))} classes")
        
        return X_scaled, y_encoded, feature_columns
    
    def _robust_clean_data(self, X):
        """Robust data cleaning that handles all edge cases"""
        print("     🔍 Applying robust data cleaning...")
        
        # Replace infinite values
        X = X.replace([np.inf, -np.inf], np.nan)
        
        # Handle each column individually
        for col in X.columns:
            # Check if column is numeric
            if pd.api.types.is_numeric_dtype(X[col]):
                # Replace NaN with median
                if X[col].isna().any():
                    median_val = X[col].median()
                    if pd.isna(median_val):
                        X[col] = 0  # If median is also NaN, use 0
                    else:
                        X[col] = X[col].fillna(median_val)
                
                # Clip extreme values
                q1 = X[col].quantile(0.01)
                q99 = X[col].quantile(0.99)
                X[col] = X[col].clip(lower=q1, upper=q99)
            else:
                # For non-numeric columns, fill with mode or 0
                X[col] = X[col].fillna(0)
        
        # Final check for any remaining issues
        X = X.replace([np.inf, -np.inf], 0)
        X = X.fillna(0)
        
        return X
    
    def _create_simple_advanced_features(self, X, feature_names):
        """Create simple but effective advanced features"""
        df = pd.DataFrame(X, columns=feature_names)
        
        # Basic ratio features (with safe division)
        if 'Total Fwd Packets' in df.columns and 'Total Backward Packets' in df.columns:
            df['Packet_Ratio'] = np.where(
                df['Total Backward Packets'] > 0,
                df['Total Fwd Packets'] / df['Total Backward Packets'],
                0
            )
            df['Packet_Diff'] = df['Total Fwd Packets'] - df['Total Backward Packets']
        
        if 'Total Length of Fwd Packets' in df.columns and 'Total Length of Bwd Packets' in df.columns:
            df['Byte_Ratio'] = np.where(
                df['Total Length of Bwd Packets'] > 0,
                df['Total Length of Fwd Packets'] / df['Total Length of Bwd Packets'],
                0
            )
            df['Byte_Diff'] = df['Total Length of Fwd Packets'] - df['Total Length of Bwd Packets']
        
        # Rate features (with safe division)
        if 'Flow Duration' in df.columns:
            duration_safe = np.where(df['Flow Duration'] > 0, df['Flow Duration'], 1)
            
            if 'Total Fwd Packets' in df.columns:
                df['Fwd_Packets_Per_Second'] = df['Total Fwd Packets'] / duration_safe
            if 'Total Backward Packets' in df.columns:
                df['Bwd_Packets_Per_Second'] = df['Total Backward Packets'] / duration_safe
            if 'Total Length of Fwd Packets' in df.columns:
                df['Fwd_Bytes_Per_Second'] = df['Total Length of Fwd Packets'] / duration_safe
            if 'Total Length of Bwd Packets' in df.columns:
                df['Bwd_Bytes_Per_Second'] = df['Total Length of Bwd Packets'] / duration_safe
        
        # Protocol features
        if 'Destination Port' in df.columns:
            df['Is_HTTP'] = df['Destination Port'].isin([80, 8080, 443, 8443]).astype(int)
            df['Is_SSH'] = (df['Destination Port'] == 22).astype(int)
            df['Is_DNS'] = (df['Destination Port'] == 53).astype(int)
            df['Is_Popular_Port'] = df['Destination Port'].isin([80, 443, 22, 21, 25, 53]).astype(int)
        
        # Statistical features
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        if len(numeric_cols) > 0:
            df['Feature_Mean'] = df[numeric_cols].mean(axis=1)
            df['Feature_Std'] = df[numeric_cols].std(axis=1)
            df['Feature_Max'] = df[numeric_cols].max(axis=1)
            df['Feature_Min'] = df[numeric_cols].min(axis=1)
        
        # Final cleanup
        df = df.replace([np.inf, -np.inf], 0)
        df = df.fillna(0)
        
        # Clip extreme values
        for col in df.select_dtypes(include=[np.number]).columns:
            df[col] = np.clip(df[col], -1e6, 1e6)
        
        return df.values
    
    def train_robust_models(self, X, y):
        """Train robust ML models"""
        print("🤖 Training robust ML models...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"📊 Training set: {X_train.shape}")
        print(f"📊 Test set: {X_test.shape}")
        
        # Feature selection
        print("🔍 Performing feature selection...")
        self.feature_selector = SelectKBest(score_func=f_classif, k=min(30, X_train.shape[1]))
        X_train_selected = self.feature_selector.fit_transform(X_train, y_train)
        X_test_selected = self.feature_selector.transform(X_test)
        
        print(f"✅ Selected {X_train_selected.shape[1]} features from {X_train.shape[1]}")
        
        # Define models
        models = {
            'RandomForest': RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                class_weight='balanced',
                n_jobs=-1
            ),
            'XGBoost': xgb.XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                random_state=42,
                eval_metric='mlogloss'
            ),
            'LogisticRegression': LogisticRegression(
                max_iter=1000,
                class_weight='balanced',
                random_state=42,
                solver='liblinear'
            )
        }
        
        # Train each model
        model_scores = {}
        for name, model in models.items():
            print(f"🚀 Training {name}...")
            
            try:
                # Train model
                model.fit(X_train_selected, y_train)
                
                # Evaluate
                y_pred = model.predict(X_test_selected)
                accuracy = accuracy_score(y_test, y_pred)
                
                model_scores[name] = {'accuracy': accuracy}
                print(f"   ✅ {name} - Accuracy: {accuracy:.4f}")
                
                # Save model
                joblib.dump(model, f"{self.model_save_path}/{name.lower()}_robust_model.pkl")
                
            except Exception as e:
                print(f"   ❌ {name} failed: {e}")
                model_scores[name] = {'accuracy': 0.0}
        
        # Create simple ensemble (just use the best model)
        best_model_name = max(model_scores.keys(), key=lambda k: model_scores[k]['accuracy'])
        best_model = models[best_model_name]
        
        print(f"🏆 Best model: {best_model_name} with accuracy {model_scores[best_model_name]['accuracy']:.4f}")
        
        # Save best model as ensemble
        joblib.dump(best_model, f"{self.model_save_path}/ensemble_robust_model.pkl")
        
        # Store models
        self.models = models
        self.models['Ensemble'] = best_model
        
        # Generate report
        self._generate_robust_classification_report(y_test, best_model.predict(X_test_selected))
        
        # Store training history
        self.training_history = {
            'model_scores': model_scores,
            'best_model': best_model_name,
            'best_accuracy': model_scores[best_model_name]['accuracy'],
            'feature_count': X_train_selected.shape[1],
            'total_features': X_train.shape[1]
        }
        
        return model_scores
    
    def _generate_robust_classification_report(self, y_true, y_pred):
        """Generate classification report"""
        print("\n" + "="*60)
        print("📊 CLASSIFICATION REPORT")
        print("="*60)
        
        # Get label names
        label_names = self.label_encoder.classes_
        
        print(classification_report(y_true, y_pred, target_names=label_names))
        
        # Confusion Matrix
        cm = confusion_matrix(y_true, y_pred)
        plt.figure(figsize=(10, 8))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                   xticklabels=label_names, yticklabels=label_names)
        plt.title('Confusion Matrix - Robust ML Model')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.xticks(rotation=45)
        plt.yticks(rotation=0)
        plt.tight_layout()
        plt.savefig(f"{self.model_save_path}/confusion_matrix_robust.png", dpi=300, bbox_inches='tight')
        plt.show()
    
    def save_robust_models(self):
        """Save all trained models and preprocessing objects"""
        print("💾 Saving robust models and preprocessing objects...")
        
        joblib.dump(self.scaler, f"{self.model_save_path}/scaler_robust.pkl")
        joblib.dump(self.label_encoder, f"{self.model_save_path}/label_encoder_robust.pkl")
        joblib.dump(self.feature_selector, f"{self.model_save_path}/feature_selector_robust.pkl")
        joblib.dump(self.training_history, f"{self.model_save_path}/training_history_robust.pkl")
        
        print("✅ Robust models saved successfully!")

def main():
    """Main function to run the robust ML system"""
    print("🛡️ Robust AI-Powered Intrusion Detection System")
    print("="*60)
    
    # Initialize the system
    ids = RobustMLIDS()
    
    try:
        # Load and preprocess data
        print("📊 Loading data...")
        network_data = ids.load_robust_data(sample_size=50000)  # Smaller sample for reliability
        
        # Preprocess data
        X, y, feature_columns = ids.preprocess_robust_data()
        
        # Train models
        model_scores = ids.train_robust_models(X, y)
        
        # Save models
        ids.save_robust_models()
        
        print("\n🎉 Robust ML training completed successfully!")
        print("📊 Model Performance Summary:")
        for model_name, scores in model_scores.items():
            print(f"   {model_name}: Accuracy={scores['accuracy']:.4f}")
        
        print(f"\n🏆 Best Model: {ids.training_history['best_model']}")
        print(f"🎯 Features used: {ids.training_history['feature_count']} (from {ids.training_history['total_features']})")
        
    except Exception as e:
        print(f"❌ Error during robust ML training: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
