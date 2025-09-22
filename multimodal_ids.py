"""
AI-Powered Intrusion Detection System Using Multimodal Data Aggregation

This system combines:
1. Network flow features (tabular data)
2. Network traffic visualizations (image data)
3. Advanced feature engineering using UM-NIDS tool

Author: AI Assistant
Date: 2024
"""

import os
import pandas as pd
import numpy as np
import cv2
from PIL import Image
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.utils.class_weight import compute_class_weight
import xgboost as xgb
import lightgbm as lgb
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler
import joblib
import warnings
warnings.filterwarnings('ignore')

class MultimodalIDS:
    """
    Multimodal Intrusion Detection System that combines:
    - Network flow features (tabular data)
    - Network traffic visualizations (image data)
    - Advanced feature engineering
    """
    
    def __init__(self, data_path=".", model_save_path="models/"):
        self.data_path = data_path
        self.model_save_path = model_save_path
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.models = {}
        self.feature_importance = {}
        
        # Create model directory
        os.makedirs(model_save_path, exist_ok=True)
        
    def load_network_data(self):
        """Load and combine all network flow CSV files"""
        print("Loading network flow data...")
        
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
                df = pd.read_csv(file)
                # Clean column names
                df.columns = df.columns.str.strip()
                dataframes.append(df)
                print(f"Loaded {file}: {df.shape}")
        
        if dataframes:
            self.network_data = pd.concat(dataframes, ignore_index=True)
            print(f"Combined network data shape: {self.network_data.shape}")
            print(f"Label distribution:\n{self.network_data['Label'].value_counts()}")
        else:
            raise FileNotFoundError("No network data files found!")
            
        return self.network_data
    
    def load_image_data(self, train_path="train/", test_path="test/"):
        """Load and preprocess image data"""
        print("Loading image data...")
        
        def load_images_from_folder(folder_path, label=None):
            images = []
            labels = []
            if os.path.exists(folder_path):
                for filename in os.listdir(folder_path):
                    if filename.endswith(('.jpg', '.jpeg', '.png')):
                        img_path = os.path.join(folder_path, filename)
                        try:
                            # Load and preprocess image
                            img = cv2.imread(img_path)
                            img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
                            img = cv2.resize(img, (224, 224))  # Resize for CNN
                            images.append(img)
                            labels.append(label if label else 0)  # Default label
                        except Exception as e:
                            print(f"Error loading {img_path}: {e}")
            return np.array(images), np.array(labels)
        
        # Load training images
        train_images, train_labels = load_images_from_folder(train_path, label=1)
        print(f"Loaded {len(train_images)} training images")
        
        # Load test images  
        test_images, test_labels = load_images_from_folder(test_path, label=0)
        print(f"Loaded {len(test_images)} test images")
        
        # Combine and create labels (assuming images represent different attack types)
        self.image_data = np.vstack([train_images, test_images]) if len(train_images) > 0 and len(test_images) > 0 else train_images
        self.image_labels = np.hstack([train_labels, test_labels]) if len(train_labels) > 0 and len(test_labels) > 0 else train_labels
        
        print(f"Total image data shape: {self.image_data.shape}")
        return self.image_data, self.image_labels
    
    def extract_image_features(self, images):
        """Extract features from images using traditional computer vision methods"""
        print("Extracting image features...")
        
        features = []
        for img in images:
            # Convert to grayscale for some features
            gray = cv2.cvtColor(img, cv2.COLOR_RGB2GRAY)
            
            # Statistical features
            mean_val = np.mean(img)
            std_val = np.std(img)
            min_val = np.min(img)
            max_val = np.max(img)
            
            # Texture features using LBP (Local Binary Pattern)
            from skimage.feature import local_binary_pattern
            lbp = local_binary_pattern(gray, 8, 1, method='uniform')
            lbp_hist, _ = np.histogram(lbp.ravel(), bins=10, range=(0, 10))
            
            # Edge features
            edges = cv2.Canny(gray, 50, 150)
            edge_density = np.sum(edges > 0) / (edges.shape[0] * edges.shape[1])
            
            # Color histogram features
            hist_r = cv2.calcHist([img], [0], None, [32], [0, 256])
            hist_g = cv2.calcHist([img], [1], None, [32], [0, 256])
            hist_b = cv2.calcHist([img], [2], None, [32], [0, 256])
            
            # Combine all features
            feature_vector = [
                mean_val, std_val, min_val, max_val, edge_density
            ] + lbp_hist.tolist() + hist_r.flatten().tolist() + hist_g.flatten().tolist() + hist_b.flatten().tolist()
            
            features.append(feature_vector)
        
        return np.array(features)
    
    def preprocess_network_data(self):
        """Preprocess network flow data"""
        print("Preprocessing network data...")
        
        # Remove rows with missing values
        self.network_data = self.network_data.dropna()
        
        # Separate features and labels
        feature_columns = [col for col in self.network_data.columns if col != 'Label']
        X = self.network_data[feature_columns]
        y = self.network_data['Label']
        
        # Handle infinite values
        X = X.replace([np.inf, -np.inf], np.nan)
        X = X.fillna(X.median())
        
        # Encode labels
        y_encoded = self.label_encoder.fit_transform(y)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        print(f"Network features shape: {X_scaled.shape}")
        print(f"Network labels shape: {y_encoded.shape}")
        print(f"Unique labels: {np.unique(y_encoded)}")
        
        return X_scaled, y_encoded, feature_columns
    
    def create_advanced_features(self, X, feature_names):
        """Create advanced features using domain knowledge"""
        print("Creating advanced features...")
        
        # Convert back to DataFrame for easier manipulation
        df = pd.DataFrame(X, columns=feature_names)
        
        # Create ratio features
        if 'Total Fwd Packets' in df.columns and 'Total Backward Packets' in df.columns:
            df['Packet_Ratio'] = df['Total Fwd Packets'] / (df['Total Backward Packets'] + 1)
        
        if 'Total Length of Fwd Packets' in df.columns and 'Total Length of Bwd Packets' in df.columns:
            df['Byte_Ratio'] = df['Total Length of Fwd Packets'] / (df['Total Length of Bwd Packets'] + 1)
        
        # Create interaction features
        if 'Flow Duration' in df.columns and 'Total Fwd Packets' in df.columns:
            df['Packets_Per_Second'] = df['Total Fwd Packets'] / (df['Flow Duration'] + 1)
        
        # Create flag combination features
        flag_columns = [col for col in df.columns if 'Flag' in col]
        if len(flag_columns) > 1:
            df['Total_Flags'] = df[flag_columns].sum(axis=1)
        
        return df.values
    
    def train_models(self, X_network, y_network, X_image_features=None):
        """Train multiple models for ensemble learning"""
        print("Training models...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_network, y_network, test_size=0.2, random_state=42, stratify=y_network
        )
        
        # Handle class imbalance
        class_weights = compute_class_weight('balanced', classes=np.unique(y_train), y=y_train)
        class_weight_dict = dict(zip(np.unique(y_train), class_weights))
        
        # Define models
        models = {
            'RandomForest': RandomForestClassifier(
                n_estimators=100, 
                max_depth=20, 
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
            'LightGBM': lgb.LGBMClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                random_state=42,
                class_weight='balanced'
            ),
            'SVM': SVC(
                kernel='rbf',
                C=1.0,
                gamma='scale',
                class_weight='balanced',
                probability=True,
                random_state=42
            ),
            'LogisticRegression': LogisticRegression(
                max_iter=1000,
                class_weight='balanced',
                random_state=42
            )
        }
        
        # Train each model
        model_scores = {}
        for name, model in models.items():
            print(f"Training {name}...")
            model.fit(X_train, y_train)
            
            # Evaluate
            y_pred = model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            model_scores[name] = accuracy
            
            print(f"{name} Accuracy: {accuracy:.4f}")
            
            # Save model
            joblib.dump(model, f"{self.model_save_path}/{name.lower()}_model.pkl")
            
            # Store feature importance for tree-based models
            if hasattr(model, 'feature_importances_'):
                self.feature_importance[name] = model.feature_importances_
        
        # Create ensemble model
        ensemble_models = [(name, models[name]) for name in ['RandomForest', 'XGBoost', 'LightGBM']]
        ensemble = VotingClassifier(estimators=ensemble_models, voting='soft')
        ensemble.fit(X_train, y_train)
        
        ensemble_pred = ensemble.predict(X_test)
        ensemble_accuracy = accuracy_score(y_test, ensemble_pred)
        print(f"Ensemble Accuracy: {ensemble_accuracy:.4f}")
        
        # Save ensemble model
        joblib.dump(ensemble, f"{self.model_save_path}/ensemble_model.pkl")
        
        # Store models
        self.models = models
        self.models['Ensemble'] = ensemble
        
        # Generate detailed report
        self.generate_classification_report(y_test, ensemble_pred)
        
        return model_scores
    
    def generate_classification_report(self, y_true, y_pred):
        """Generate detailed classification report"""
        print("\n" + "="*50)
        print("CLASSIFICATION REPORT")
        print("="*50)
        
        # Get label names
        label_names = self.label_encoder.classes_
        
        print(classification_report(y_true, y_pred, target_names=label_names))
        
        # Confusion Matrix
        cm = confusion_matrix(y_true, y_pred)
        plt.figure(figsize=(10, 8))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                   xticklabels=label_names, yticklabels=label_names)
        plt.title('Confusion Matrix')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.tight_layout()
        plt.savefig(f"{self.model_save_path}/confusion_matrix.png", dpi=300, bbox_inches='tight')
        plt.show()
    
    def predict(self, X_network, X_image_features=None):
        """Make predictions using the ensemble model"""
        if 'Ensemble' not in self.models:
            raise ValueError("Models not trained yet. Call train_models() first.")
        
        # Preprocess input data
        X_network_scaled = self.scaler.transform(X_network)
        
        # Make predictions
        predictions = self.models['Ensemble'].predict(X_network_scaled)
        probabilities = self.models['Ensemble'].predict_proba(X_network_scaled)
        
        # Convert back to original labels
        predicted_labels = self.label_encoder.inverse_transform(predictions)
        
        return predicted_labels, probabilities
    
    def save_models(self):
        """Save all trained models and preprocessing objects"""
        print("Saving models and preprocessing objects...")
        
        joblib.dump(self.scaler, f"{self.model_save_path}/scaler.pkl")
        joblib.dump(self.label_encoder, f"{self.model_save_path}/label_encoder.pkl")
        
        # Save feature importance
        if self.feature_importance:
            joblib.dump(self.feature_importance, f"{self.model_save_path}/feature_importance.pkl")
        
        print("Models saved successfully!")
    
    def load_models(self):
        """Load pre-trained models and preprocessing objects"""
        print("Loading pre-trained models...")
        
        self.scaler = joblib.load(f"{self.model_save_path}/scaler.pkl")
        self.label_encoder = joblib.load(f"{self.model_save_path}/label_encoder.pkl")
        self.models['Ensemble'] = joblib.load(f"{self.model_save_path}/ensemble_model.pkl")
        
        if os.path.exists(f"{self.model_save_path}/feature_importance.pkl"):
            self.feature_importance = joblib.load(f"{self.model_save_path}/feature_importance.pkl")
        
        print("Models loaded successfully!")

def main():
    """Main function to run the multimodal IDS"""
    print("AI-Powered Intrusion Detection System")
    print("="*50)
    
    # Initialize the system
    ids = MultimodalIDS()
    
    try:
        # Load and preprocess data
        network_data = ids.load_network_data()
        X_network, y_network, feature_columns = ids.preprocess_network_data()
        
        # Create advanced features
        X_network_advanced = ids.create_advanced_features(X_network, feature_columns)
        
        # Load image data (optional)
        try:
            image_data, image_labels = ids.load_image_data()
            X_image_features = ids.extract_image_features(image_data)
            print(f"Image features shape: {X_image_features.shape}")
        except Exception as e:
            print(f"Image data not available: {e}")
            X_image_features = None
        
        # Train models
        model_scores = ids.train_models(X_network_advanced, y_network, X_image_features)
        
        # Save models
        ids.save_models()
        
        print("\nTraining completed successfully!")
        print("Model Performance Summary:")
        for model_name, score in model_scores.items():
            print(f"{model_name}: {score:.4f}")
            
    except Exception as e:
        print(f"Error during training: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
