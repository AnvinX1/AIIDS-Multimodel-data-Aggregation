"""
🛡️ Real AI-Powered Intrusion Detection System
Complete ML implementation with actual data processing and model training
"""

import os
import pandas as pd
import numpy as np
import cv2
from PIL import Image
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.preprocessing import StandardScaler, LabelEncoder, MinMaxScaler
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score
from sklearn.utils.class_weight import compute_class_weight
from sklearn.feature_selection import SelectKBest, f_classif, mutual_info_classif
from sklearn.decomposition import PCA
import xgboost as xgb
import lightgbm as lgb
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler
import joblib
import warnings
warnings.filterwarnings('ignore')

class RealMLIDS:
    """
    Real AI-Powered Intrusion Detection System
    Complete implementation with actual ML models and data processing
    """
    
    def __init__(self, data_path=".", model_save_path="models/"):
        self.data_path = data_path
        self.model_save_path = model_save_path
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_selector = None
        self.pca = None
        self.models = {}
        self.feature_importance = {}
        self.training_history = {}
        
        # Create model directory
        os.makedirs(model_save_path, exist_ok=True)
        
    def load_real_data(self):
        """Load and process real network flow data"""
        print("🔄 Loading real network flow data...")
        
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
        for file in csv_files:
            if os.path.exists(file):
                print(f"📊 Loading {file}...")
                df = pd.read_csv(file)
                df.columns = df.columns.str.strip()
                dataframes.append(df)
                print(f"   ✅ Loaded: {df.shape[0]} flows, {df.shape[1]} features")
        
        if dataframes:
            self.network_data = pd.concat(dataframes, ignore_index=True)
            print(f"🎯 Combined dataset: {self.network_data.shape[0]} flows, {self.network_data.shape[1]} features")
            
            # Show label distribution
            label_counts = self.network_data['Label'].value_counts()
            print(f"📈 Attack type distribution:")
            for label, count in label_counts.items():
                percentage = (count / len(self.network_data)) * 100
                print(f"   {label}: {count:,} ({percentage:.1f}%)")
            
            return self.network_data
        else:
            raise FileNotFoundError("❌ No network data files found!")
    
    def load_real_image_data(self):
        """Load and process real image data"""
        print("🖼️ Loading real image data...")
        
        def load_images_from_folder(folder_path, label_prefix=""):
            images = []
            labels = []
            if os.path.exists(folder_path):
                files = [f for f in os.listdir(folder_path) if f.endswith(('.jpg', '.jpeg', '.png'))]
                print(f"   📁 Found {len(files)} images in {folder_path}")
                
                for i, filename in enumerate(files[:1000]):  # Limit to 1000 for performance
                    img_path = os.path.join(folder_path, filename)
                    try:
                        img = cv2.imread(img_path)
                        if img is not None:
                            img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
                            img = cv2.resize(img, (224, 224))
                            images.append(img)
                            labels.append(f"{label_prefix}{i}")
                    except Exception as e:
                        print(f"   ⚠️ Error loading {filename}: {e}")
            
            return np.array(images), np.array(labels)
        
        # Load training images
        train_images, train_labels = load_images_from_folder("train/", "train_")
        print(f"✅ Loaded {len(train_images)} training images")
        
        # Load test images  
        test_images, test_labels = load_images_from_folder("test/", "test_")
        print(f"✅ Loaded {len(test_images)} test images")
        
        # Combine if we have both
        if len(train_images) > 0 and len(test_images) > 0:
            self.image_data = np.vstack([train_images, test_images])
            self.image_labels = np.hstack([train_labels, test_labels])
        elif len(train_images) > 0:
            self.image_data = train_images
            self.image_labels = train_labels
        else:
            self.image_data = np.array([])
            self.image_labels = np.array([])
        
        print(f"🎯 Total image data: {self.image_data.shape}")
        return self.image_data, self.image_labels
    
    def extract_real_image_features(self, images):
        """Extract real features from images using computer vision"""
        print("🔍 Extracting real image features...")
        
        features = []
        for i, img in enumerate(images):
            if i % 100 == 0:
                print(f"   Processing image {i+1}/{len(images)}")
            
            # Convert to grayscale for some features
            gray = cv2.cvtColor(img, cv2.COLOR_RGB2GRAY)
            
            # Statistical features
            basic_features = [
                np.mean(img), np.std(img), np.min(img), np.max(img),
                np.mean(gray), np.std(gray), np.min(gray), np.max(gray)
            ]
            
            # Texture features using LBP
            try:
                from skimage.feature import local_binary_pattern
                lbp = local_binary_pattern(gray, 8, 1, method='uniform')
                lbp_hist, _ = np.histogram(lbp.ravel(), bins=10, range=(0, 10))
                texture_features = lbp_hist.tolist()
            except ImportError:
                texture_features = [0] * 10
            
            # Edge features
            edges = cv2.Canny(gray, 50, 150)
            edge_density = np.sum(edges > 0) / (edges.shape[0] * edges.shape[1])
            
            # Sobel edges
            sobel_x = cv2.Sobel(gray, cv2.CV_64F, 1, 0, ksize=3)
            sobel_y = cv2.Sobel(gray, cv2.CV_64F, 0, 1, ksize=3)
            sobel_magnitude = np.sqrt(sobel_x**2 + sobel_y**2)
            sobel_mean = np.mean(sobel_magnitude)
            sobel_std = np.std(sobel_magnitude)
            
            edge_features = [edge_density, sobel_mean, sobel_std]
            
            # Color features
            hist_r = cv2.calcHist([img], [0], None, [32], [0, 256])
            hist_g = cv2.calcHist([img], [1], None, [32], [0, 256])
            hist_b = cv2.calcHist([img], [2], None, [32], [0, 256])
            
            # Color moments
            r_mean, r_std = np.mean(img[:,:,0]), np.std(img[:,:,0])
            g_mean, g_std = np.mean(img[:,:,1]), np.std(img[:,:,1])
            b_mean, b_std = np.mean(img[:,:,2]), np.std(img[:,:,2])
            
            color_features = (hist_r.flatten().tolist() + hist_g.flatten().tolist() + 
                            hist_b.flatten().tolist() + [r_mean, r_std, g_mean, g_std, b_mean, b_std])
            
            # Combine all features
            feature_vector = basic_features + texture_features + edge_features + color_features
            features.append(feature_vector)
        
        return np.array(features)
    
    def preprocess_real_data(self):
        """Preprocess real network data with advanced feature engineering"""
        print("🔧 Preprocessing real network data...")
        
        # Clean data
        print("   🧹 Cleaning data...")
        self.network_data = self.network_data.dropna()
        print(f"   ✅ After cleaning: {self.network_data.shape}")
        
        # Separate features and labels
        feature_columns = [col for col in self.network_data.columns if col != 'Label']
        X = self.network_data[feature_columns]
        y = self.network_data['Label']
        
        # Handle infinite values
        print("   🔄 Handling infinite values...")
        X = X.replace([np.inf, -np.inf], np.nan)
        X = X.fillna(X.median())
        
        # Create advanced features
        print("   🚀 Creating advanced features...")
        X_advanced = self._create_real_advanced_features(X, feature_columns)
        
        # Encode labels
        print("   🏷️ Encoding labels...")
        y_encoded = self.label_encoder.fit_transform(y)
        
        # Scale features
        print("   📏 Scaling features...")
        X_scaled = self.scaler.fit_transform(X_advanced)
        
        print(f"✅ Preprocessed data: {X_scaled.shape}")
        print(f"✅ Labels: {len(np.unique(y_encoded))} classes")
        
        return X_scaled, y_encoded, feature_columns
    
    def _create_real_advanced_features(self, X, feature_names):
        """Create real advanced features using domain knowledge"""
        df = pd.DataFrame(X, columns=feature_names)
        
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
        df['Feature_Mean'] = df[numeric_cols].mean(axis=1)
        df['Feature_Std'] = df[numeric_cols].std(axis=1)
        df['Feature_Min'] = df[numeric_cols].min(axis=1)
        df['Feature_Max'] = df[numeric_cols].max(axis=1)
        df['Feature_Range'] = df['Feature_Max'] - df['Feature_Min']
        df['Feature_CV'] = df['Feature_Std'] / (df['Feature_Mean'] + 1e-8)
        
        return df.values
    
    def train_real_models(self, X, y):
        """Train real ML models with proper validation"""
        print("🤖 Training real ML models...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"📊 Training set: {X_train.shape}")
        print(f"📊 Test set: {X_test.shape}")
        
        # Handle class imbalance
        class_weights = compute_class_weight('balanced', classes=np.unique(y_train), y=y_train)
        class_weight_dict = dict(zip(np.unique(y_train), class_weights))
        
        # Feature selection
        print("🔍 Performing feature selection...")
        self.feature_selector = SelectKBest(score_func=mutual_info_classif, k=min(50, X_train.shape[1]))
        X_train_selected = self.feature_selector.fit_transform(X_train, y_train)
        X_test_selected = self.feature_selector.transform(X_test)
        
        print(f"✅ Selected {X_train_selected.shape[1]} features from {X_train.shape[1]}")
        
        # Define models with hyperparameter tuning
        models = {
            'RandomForest': RandomForestClassifier(
                n_estimators=200,
                max_depth=25,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                class_weight='balanced',
                n_jobs=-1
            ),
            'XGBoost': xgb.XGBClassifier(
                n_estimators=200,
                max_depth=8,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=42,
                eval_metric='mlogloss'
            ),
            'LightGBM': lgb.LGBMClassifier(
                n_estimators=200,
                max_depth=8,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=42,
                class_weight='balanced',
                verbose=-1
            ),
            'SVM': SVC(
                kernel='rbf',
                C=10.0,
                gamma='scale',
                class_weight='balanced',
                probability=True,
                random_state=42
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
            
            # Train model
            model.fit(X_train_selected, y_train)
            
            # Evaluate
            y_pred = model.predict(X_test_selected)
            y_pred_proba = model.predict_proba(X_test_selected)
            
            accuracy = accuracy_score(y_test, y_pred)
            try:
                auc = roc_auc_score(y_test, y_pred_proba, multi_class='ovr', average='weighted')
            except:
                auc = 0.0
            
            model_scores[name] = {'accuracy': accuracy, 'auc': auc}
            
            print(f"   ✅ {name} - Accuracy: {accuracy:.4f}, AUC: {auc:.4f}")
            
            # Save model
            joblib.dump(model, f"{self.model_save_path}/{name.lower()}_real_model.pkl")
            
            # Store feature importance for tree-based models
            if hasattr(model, 'feature_importances_'):
                self.feature_importance[name] = model.feature_importances_
        
        # Create ensemble model
        print("🎯 Creating ensemble model...")
        ensemble_models = [(name, models[name]) for name in ['RandomForest', 'XGBoost', 'LightGBM']]
        ensemble = VotingClassifier(estimators=ensemble_models, voting='soft')
        ensemble.fit(X_train_selected, y_train)
        
        ensemble_pred = ensemble.predict(X_test_selected)
        ensemble_pred_proba = ensemble.predict_proba(X_test_selected)
        ensemble_accuracy = accuracy_score(y_test, ensemble_pred)
        try:
            ensemble_auc = roc_auc_score(y_test, ensemble_pred_proba, multi_class='ovr', average='weighted')
        except:
            ensemble_auc = 0.0
        
        print(f"✅ Ensemble - Accuracy: {ensemble_accuracy:.4f}, AUC: {ensemble_auc:.4f}")
        
        # Save ensemble model
        joblib.dump(ensemble, f"{self.model_save_path}/ensemble_real_model.pkl")
        
        # Store models
        self.models = models
        self.models['Ensemble'] = ensemble
        
        # Generate detailed report
        self._generate_real_classification_report(y_test, ensemble_pred, ensemble_pred_proba)
        
        # Store training history
        self.training_history = {
            'model_scores': model_scores,
            'ensemble_accuracy': ensemble_accuracy,
            'ensemble_auc': ensemble_auc,
            'feature_count': X_train_selected.shape[1],
            'total_features': X_train.shape[1]
        }
        
        return model_scores
    
    def _generate_real_classification_report(self, y_true, y_pred, y_pred_proba):
        """Generate detailed classification report"""
        print("\n" + "="*60)
        print("📊 DETAILED CLASSIFICATION REPORT")
        print("="*60)
        
        # Get label names
        label_names = self.label_encoder.classes_
        
        print(classification_report(y_true, y_pred, target_names=label_names))
        
        # Confusion Matrix
        cm = confusion_matrix(y_true, y_pred)
        plt.figure(figsize=(12, 10))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                   xticklabels=label_names, yticklabels=label_names)
        plt.title('Confusion Matrix - Real ML Model')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.xticks(rotation=45)
        plt.yticks(rotation=0)
        plt.tight_layout()
        plt.savefig(f"{self.model_save_path}/confusion_matrix_real.png", dpi=300, bbox_inches='tight')
        plt.show()
        
        # Feature importance plot
        if self.feature_importance:
            self._plot_feature_importance()
    
    def _plot_feature_importance(self):
        """Plot feature importance for tree-based models"""
        print("📈 Plotting feature importance...")
        
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        axes = axes.ravel()
        
        for i, (name, importance) in enumerate(self.feature_importance.items()):
            if i < 4:  # Limit to 4 plots
                # Get top 20 features
                top_indices = np.argsort(importance)[-20:]
                top_importance = importance[top_indices]
                
                axes[i].barh(range(len(top_importance)), top_importance)
                axes[i].set_title(f'{name} - Top 20 Features')
                axes[i].set_xlabel('Importance')
                axes[i].set_ylabel('Feature Index')
        
        plt.tight_layout()
        plt.savefig(f"{self.model_save_path}/feature_importance_real.png", dpi=300, bbox_inches='tight')
        plt.show()
    
    def predict_real_anomaly(self, flow_data):
        """Make real predictions using trained models"""
        try:
            # Convert to DataFrame
            df = pd.DataFrame([flow_data])
            df.columns = df.columns.str.strip()
            
            # Handle missing values
            df = df.fillna(0)
            df = df.replace([np.inf, -np.inf], 0)
            
            # Create advanced features
            feature_columns = [col for col in df.columns if col != 'Label']
            X_advanced = self._create_real_advanced_features(df[feature_columns], feature_columns)
            
            # Scale features
            X_scaled = self.scaler.transform(X_advanced)
            
            # Select features
            X_selected = self.feature_selector.transform(X_scaled)
            
            # Make prediction
            prediction = self.models['Ensemble'].predict(X_selected)[0]
            probabilities = self.models['Ensemble'].predict_proba(X_selected)[0]
            
            # Get predicted label
            predicted_label = self.label_encoder.inverse_transform([prediction])[0]
            confidence = np.max(probabilities)
            
            # Create result
            result = {
                'predicted_label': predicted_label,
                'confidence': float(confidence),
                'is_anomaly': predicted_label != 'BENIGN',
                'risk_level': self._calculate_real_risk_level(confidence, predicted_label),
                'all_probabilities': {
                    label: float(prob) for label, prob in 
                    zip(self.label_encoder.classes_, probabilities)
                },
                'model_used': 'Real Ensemble Model'
            }
            
            return result
            
        except Exception as e:
            return {
                'error': str(e),
                'predicted_label': 'ERROR',
                'confidence': 0.0,
                'is_anomaly': False,
                'risk_level': 'UNKNOWN'
            }
    
    def _calculate_real_risk_level(self, confidence, label):
        """Calculate real risk level based on confidence and label"""
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
    
    def save_real_models(self):
        """Save all trained models and preprocessing objects"""
        print("💾 Saving real models and preprocessing objects...")
        
        joblib.dump(self.scaler, f"{self.model_save_path}/scaler_real.pkl")
        joblib.dump(self.label_encoder, f"{self.model_save_path}/label_encoder_real.pkl")
        joblib.dump(self.feature_selector, f"{self.model_save_path}/feature_selector_real.pkl")
        
        # Save feature importance
        if self.feature_importance:
            joblib.dump(self.feature_importance, f"{self.model_save_path}/feature_importance_real.pkl")
        
        # Save training history
        joblib.dump(self.training_history, f"{self.model_save_path}/training_history_real.pkl")
        
        print("✅ Real models saved successfully!")
    
    def load_real_models(self):
        """Load pre-trained real models and preprocessing objects"""
        print("📂 Loading pre-trained real models...")
        
        try:
            self.scaler = joblib.load(f"{self.model_save_path}/scaler_real.pkl")
            self.label_encoder = joblib.load(f"{self.model_save_path}/label_encoder_real.pkl")
            self.feature_selector = joblib.load(f"{self.model_save_path}/feature_selector_real.pkl")
            self.models['Ensemble'] = joblib.load(f"{self.model_save_path}/ensemble_real_model.pkl")
            
            if os.path.exists(f"{self.model_save_path}/feature_importance_real.pkl"):
                self.feature_importance = joblib.load(f"{self.model_save_path}/feature_importance_real.pkl")
            
            if os.path.exists(f"{self.model_save_path}/training_history_real.pkl"):
                self.training_history = joblib.load(f"{self.model_save_path}/training_history_real.pkl")
            
            print("✅ Real models loaded successfully!")
            return True
        except Exception as e:
            print(f"❌ Error loading real models: {e}")
            return False

def main():
    """Main function to run the real ML system"""
    print("🛡️ Real AI-Powered Intrusion Detection System")
    print("="*60)
    
    # Initialize the system
    ids = RealMLIDS()
    
    try:
        # Load and preprocess real data
        print("📊 Loading real data...")
        network_data = ids.load_real_data()
        
        # Load image data (optional)
        try:
            image_data, image_labels = ids.load_real_image_data()
            if len(image_data) > 0:
                image_features = ids.extract_real_image_features(image_data)
                print(f"✅ Image features extracted: {image_features.shape}")
        except Exception as e:
            print(f"⚠️ Image data not available: {e}")
        
        # Preprocess network data
        X, y, feature_columns = ids.preprocess_real_data()
        
        # Train real models
        model_scores = ids.train_real_models(X, y)
        
        # Save models
        ids.save_real_models()
        
        print("\n🎉 Real ML training completed successfully!")
        print("📊 Model Performance Summary:")
        for model_name, scores in model_scores.items():
            print(f"   {model_name}: Accuracy={scores['accuracy']:.4f}, AUC={scores['auc']:.4f}")
        
        print(f"\n🏆 Ensemble Model: Accuracy={ids.training_history['ensemble_accuracy']:.4f}")
        print(f"🎯 Features used: {ids.training_history['feature_count']} (from {ids.training_history['total_features']})")
        
        # Test with sample prediction
        print("\n🔍 Testing real prediction...")
        sample_flow = network_data.iloc[0].to_dict()
        result = ids.predict_real_anomaly(sample_flow)
        print(f"   Sample prediction: {result['predicted_label']}")
        print(f"   Confidence: {result['confidence']:.4f}")
        print(f"   Risk level: {result['risk_level']}")
        
    except Exception as e:
        print(f"❌ Error during real ML training: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
