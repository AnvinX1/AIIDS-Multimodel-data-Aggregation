"""
Advanced Data Processing Module for Multimodal IDS
Handles data preprocessing, feature engineering, and integration with UM-NIDS tool
"""

import os
import pandas as pd
import numpy as np
import cv2
from PIL import Image
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler, LabelEncoder, MinMaxScaler
from sklearn.feature_selection import SelectKBest, f_classif, mutual_info_classif
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
import joblib
import warnings
warnings.filterwarnings('ignore')

class AdvancedDataProcessor:
    """
    Advanced data processing class for multimodal intrusion detection
    """
    
    def __init__(self, data_path="."):
        self.data_path = data_path
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_selector = None
        self.pca = None
        self.processed_data = {}
        
    def load_and_combine_datasets(self):
        """Load and combine all available datasets"""
        print("Loading and combining datasets...")
        
        # Load network flow data
        network_data = self._load_network_flow_data()
        
        # Load image data
        image_data, image_labels = self._load_image_data()
        
        # Process and combine
        combined_data = self._combine_multimodal_data(network_data, image_data, image_labels)
        
        return combined_data
    
    def _load_network_flow_data(self):
        """Load network flow CSV files"""
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
                df.columns = df.columns.str.strip()
                dataframes.append(df)
                print(f"Loaded {file}: {df.shape}")
        
        if dataframes:
            combined_df = pd.concat(dataframes, ignore_index=True)
            print(f"Combined network data shape: {combined_df.shape}")
            return combined_df
        else:
            raise FileNotFoundError("No network data files found!")
    
    def _load_image_data(self):
        """Load and preprocess image data"""
        def load_images_from_folder(folder_path, label=None):
            images = []
            labels = []
            if os.path.exists(folder_path):
                for filename in os.listdir(folder_path):
                    if filename.endswith(('.jpg', '.jpeg', '.png')):
                        img_path = os.path.join(folder_path, filename)
                        try:
                            img = cv2.imread(img_path)
                            img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
                            img = cv2.resize(img, (224, 224))
                            images.append(img)
                            labels.append(label if label else 0)
                        except Exception as e:
                            print(f"Error loading {img_path}: {e}")
            return np.array(images), np.array(labels)
        
        # Load training images
        train_images, train_labels = load_images_from_folder("train/", label=1)
        print(f"Loaded {len(train_images)} training images")
        
        # Load test images  
        test_images, test_labels = load_images_from_folder("test/", label=0)
        print(f"Loaded {len(test_images)} test images")
        
        # Combine
        if len(train_images) > 0 and len(test_images) > 0:
            image_data = np.vstack([train_images, test_images])
            image_labels = np.hstack([train_labels, test_labels])
        elif len(train_images) > 0:
            image_data = train_images
            image_labels = train_labels
        else:
            image_data = np.array([])
            image_labels = np.array([])
        
        print(f"Total image data shape: {image_data.shape}")
        return image_data, image_labels
    
    def _combine_multimodal_data(self, network_data, image_data, image_labels):
        """Combine network and image data"""
        combined_data = {
            'network_data': network_data,
            'image_data': image_data,
            'image_labels': image_labels
        }
        
        # If we have both types of data, create mappings
        if len(image_data) > 0 and len(network_data) > 0:
            # Create synthetic mappings between image and network data
            # This is a simplified approach - in practice, you'd have proper mappings
            combined_data['multimodal_mapping'] = self._create_multimodal_mapping(
                len(network_data), len(image_data)
            )
        
        return combined_data
    
    def _create_multimodal_mapping(self, network_size, image_size):
        """Create mapping between network and image data"""
        # Simple mapping - in practice, this would be based on timestamps or other identifiers
        mapping = {}
        for i in range(min(network_size, image_size)):
            mapping[i] = i
        return mapping
    
    def advanced_feature_engineering(self, data):
        """Perform advanced feature engineering"""
        print("Performing advanced feature engineering...")
        
        network_data = data['network_data']
        
        # Clean data
        network_data = network_data.dropna()
        
        # Separate features and labels
        feature_columns = [col for col in network_data.columns if col != 'Label']
        X = network_data[feature_columns]
        y = network_data['Label']
        
        # Handle infinite values
        X = X.replace([np.inf, -np.inf], np.nan)
        X = X.fillna(X.median())
        
        # Create advanced features
        X_advanced = self._create_advanced_features(X, feature_columns)
        
        # Create statistical features
        X_statistical = self._create_statistical_features(X_advanced)
        
        # Create temporal features
        X_temporal = self._create_temporal_features(X_advanced)
        
        # Combine all features
        X_combined = np.hstack([X_advanced, X_statistical, X_temporal])
        
        # Create feature names
        feature_names = feature_columns + self._get_advanced_feature_names() + \
                       self._get_statistical_feature_names() + self._get_temporal_feature_names()
        
        return X_combined, y, feature_names
    
    def _create_advanced_features(self, X, feature_names):
        """Create advanced domain-specific features"""
        df = pd.DataFrame(X, columns=feature_names)
        
        # Packet ratio features
        if 'Total Fwd Packets' in df.columns and 'Total Backward Packets' in df.columns:
            df['Packet_Ratio'] = df['Total Fwd Packets'] / (df['Total Backward Packets'] + 1)
            df['Packet_Diff'] = df['Total Fwd Packets'] - df['Total Backward Packets']
        
        # Byte ratio features
        if 'Total Length of Fwd Packets' in df.columns and 'Total Length of Bwd Packets' in df.columns:
            df['Byte_Ratio'] = df['Total Length of Fwd Packets'] / (df['Total Length of Bwd Packets'] + 1)
            df['Byte_Diff'] = df['Total Length of Fwd Packets'] - df['Total Length of Bwd Packets']
        
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
        
        return df.values
    
    def _create_statistical_features(self, X):
        """Create statistical features"""
        # Rolling statistics (simplified version)
        X_stats = np.zeros((X.shape[0], 4))
        
        # Mean, std, min, max for each sample
        X_stats[:, 0] = np.mean(X, axis=1)
        X_stats[:, 1] = np.std(X, axis=1)
        X_stats[:, 2] = np.min(X, axis=1)
        X_stats[:, 3] = np.max(X, axis=1)
        
        return X_stats
    
    def _create_temporal_features(self, X):
        """Create temporal features"""
        # Simplified temporal features
        X_temporal = np.zeros((X.shape[0], 2))
        
        # Coefficient of variation
        X_temporal[:, 0] = np.std(X, axis=1) / (np.mean(X, axis=1) + 1e-8)
        
        # Range
        X_temporal[:, 1] = np.max(X, axis=1) - np.min(X, axis=1)
        
        return X_temporal
    
    def _get_advanced_feature_names(self):
        """Get names of advanced features"""
        return [
            'Packet_Ratio', 'Packet_Diff', 'Byte_Ratio', 'Byte_Diff',
            'Fwd_Packets_Per_Second', 'Bwd_Packets_Per_Second',
            'Fwd_Bytes_Per_Second', 'Bwd_Bytes_Per_Second',
            'Total_Flags', 'Flag_Diversity', 'Win_Size_Ratio', 'Win_Size_Diff',
            'Is_HTTP', 'Is_SSH', 'Is_DNS', 'Is_FTP'
        ]
    
    def _get_statistical_feature_names(self):
        """Get names of statistical features"""
        return ['Mean', 'Std', 'Min', 'Max']
    
    def _get_temporal_feature_names(self):
        """Get names of temporal features"""
        return ['Coeff_Variation', 'Range']
    
    def extract_image_features(self, images):
        """Extract comprehensive features from images"""
        print("Extracting image features...")
        
        features = []
        for img in images:
            # Convert to grayscale for some features
            gray = cv2.cvtColor(img, cv2.COLOR_RGB2GRAY)
            
            # Basic statistical features
            basic_features = [
                np.mean(img), np.std(img), np.min(img), np.max(img),
                np.mean(gray), np.std(gray), np.min(gray), np.max(gray)
            ]
            
            # Texture features
            texture_features = self._extract_texture_features(gray)
            
            # Edge features
            edge_features = self._extract_edge_features(gray)
            
            # Color features
            color_features = self._extract_color_features(img)
            
            # Combine all features
            feature_vector = basic_features + texture_features + edge_features + color_features
            features.append(feature_vector)
        
        return np.array(features)
    
    def _extract_texture_features(self, gray):
        """Extract texture features using LBP and GLCM"""
        try:
            from skimage.feature import local_binary_pattern, graycomatrix, graycoprops
            
            # Local Binary Pattern
            lbp = local_binary_pattern(gray, 8, 1, method='uniform')
            lbp_hist, _ = np.histogram(lbp.ravel(), bins=10, range=(0, 10))
            
            # Gray Level Co-occurrence Matrix
            glcm = graycomatrix(gray, distances=[1], angles=[0], levels=256, symmetric=True, normed=True)
            contrast = graycoprops(glcm, 'contrast')[0, 0]
            dissimilarity = graycoprops(glcm, 'dissimilarity')[0, 0]
            homogeneity = graycoprops(glcm, 'homogeneity')[0, 0]
            energy = graycoprops(glcm, 'energy')[0, 0]
            
            return lbp_hist.tolist() + [contrast, dissimilarity, homogeneity, energy]
            
        except ImportError:
            # Fallback if scikit-image is not available
            return [0] * 14
    
    def _extract_edge_features(self, gray):
        """Extract edge features"""
        # Canny edge detection
        edges = cv2.Canny(gray, 50, 150)
        edge_density = np.sum(edges > 0) / (edges.shape[0] * edges.shape[1])
        
        # Sobel edges
        sobel_x = cv2.Sobel(gray, cv2.CV_64F, 1, 0, ksize=3)
        sobel_y = cv2.Sobel(gray, cv2.CV_64F, 0, 1, ksize=3)
        sobel_magnitude = np.sqrt(sobel_x**2 + sobel_y**2)
        sobel_mean = np.mean(sobel_magnitude)
        sobel_std = np.std(sobel_magnitude)
        
        return [edge_density, sobel_mean, sobel_std]
    
    def _extract_color_features(self, img):
        """Extract color features"""
        # Color histograms
        hist_r = cv2.calcHist([img], [0], None, [32], [0, 256])
        hist_g = cv2.calcHist([img], [1], None, [32], [0, 256])
        hist_b = cv2.calcHist([img], [2], None, [32], [0, 256])
        
        # Color moments
        r_mean, r_std = np.mean(img[:,:,0]), np.std(img[:,:,0])
        g_mean, g_std = np.mean(img[:,:,1]), np.std(img[:,:,1])
        b_mean, b_std = np.mean(img[:,:,2]), np.std(img[:,:,2])
        
        return (hist_r.flatten().tolist() + hist_g.flatten().tolist() + 
                hist_b.flatten().tolist() + [r_mean, r_std, g_mean, g_std, b_mean, b_std])
    
    def feature_selection(self, X, y, method='mutual_info', k=50):
        """Perform feature selection"""
        print(f"Performing feature selection using {method}...")
        
        if method == 'mutual_info':
            self.feature_selector = SelectKBest(score_func=mutual_info_classif, k=k)
        elif method == 'f_classif':
            self.feature_selector = SelectKBest(score_func=f_classif, k=k)
        else:
            raise ValueError("Method must be 'mutual_info' or 'f_classif'")
        
        X_selected = self.feature_selector.fit_transform(X, y)
        
        print(f"Selected {X_selected.shape[1]} features from {X.shape[1]}")
        
        return X_selected
    
    def dimensionality_reduction(self, X, method='pca', n_components=20):
        """Perform dimensionality reduction"""
        print(f"Performing dimensionality reduction using {method}...")
        
        if method == 'pca':
            self.pca = PCA(n_components=n_components, random_state=42)
            X_reduced = self.pca.fit_transform(X)
        elif method == 'tsne':
            self.pca = TSNE(n_components=n_components, random_state=42)
            X_reduced = self.pca.fit_transform(X)
        else:
            raise ValueError("Method must be 'pca' or 'tsne'")
        
        print(f"Reduced dimensions from {X.shape[1]} to {X_reduced.shape[1]}")
        
        return X_reduced
    
    def visualize_data(self, X, y, method='tsne', save_path='visualizations/'):
        """Create data visualizations"""
        print("Creating data visualizations...")
        
        os.makedirs(save_path, exist_ok=True)
        
        # Reduce dimensions for visualization
        if method == 'tsne':
            reducer = TSNE(n_components=2, random_state=42)
        elif method == 'pca':
            reducer = PCA(n_components=2, random_state=42)
        else:
            raise ValueError("Method must be 'tsne' or 'pca'")
        
        X_2d = reducer.fit_transform(X)
        
        # Create scatter plot
        plt.figure(figsize=(12, 8))
        scatter = plt.scatter(X_2d[:, 0], X_2d[:, 1], c=y, cmap='viridis', alpha=0.6)
        plt.colorbar(scatter)
        plt.title(f'Data Visualization using {method.upper()}')
        plt.xlabel(f'{method.upper()} Component 1')
        plt.ylabel(f'{method.upper()} Component 2')
        plt.tight_layout()
        plt.savefig(f"{save_path}/data_visualization_{method}.png", dpi=300, bbox_inches='tight')
        plt.show()
        
        # Create class distribution plot
        plt.figure(figsize=(10, 6))
        unique_labels, counts = np.unique(y, return_counts=True)
        plt.bar(unique_labels, counts)
        plt.title('Class Distribution')
        plt.xlabel('Class')
        plt.ylabel('Count')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(f"{save_path}/class_distribution.png", dpi=300, bbox_inches='tight')
        plt.show()
    
    def save_processed_data(self, X, y, feature_names, save_path='processed_data/'):
        """Save processed data"""
        print("Saving processed data...")
        
        os.makedirs(save_path, exist_ok=True)
        
        # Save as numpy arrays
        np.save(f"{save_path}/X_processed.npy", X)
        np.save(f"{save_path}/y_processed.npy", y)
        
        # Save feature names
        with open(f"{save_path}/feature_names.txt", 'w') as f:
            for name in feature_names:
                f.write(f"{name}\n")
        
        # Save as CSV for easy inspection
        df = pd.DataFrame(X, columns=feature_names)
        df['Label'] = y
        df.to_csv(f"{save_path}/processed_data.csv", index=False)
        
        print(f"Processed data saved to {save_path}")
    
    def load_processed_data(self, save_path='processed_data/'):
        """Load processed data"""
        print("Loading processed data...")
        
        X = np.load(f"{save_path}/X_processed.npy")
        y = np.load(f"{save_path}/y_processed.npy")
        
        with open(f"{save_path}/feature_names.txt", 'r') as f:
            feature_names = [line.strip() for line in f.readlines()]
        
        print(f"Loaded processed data: X shape {X.shape}, y shape {y.shape}")
        
        return X, y, feature_names

def main():
    """Main function to demonstrate data processing"""
    print("Advanced Data Processing for Multimodal IDS")
    print("="*50)
    
    # Initialize processor
    processor = AdvancedDataProcessor()
    
    try:
        # Load and combine datasets
        data = processor.load_and_combine_datasets()
        
        # Advanced feature engineering
        X, y, feature_names = processor.advanced_feature_engineering(data)
        
        # Feature selection
        X_selected = processor.feature_selection(X, y, method='mutual_info', k=50)
        
        # Dimensionality reduction
        X_reduced = processor.dimensionality_reduction(X_selected, method='pca', n_components=20)
        
        # Visualize data
        processor.visualize_data(X_reduced, y, method='pca')
        
        # Save processed data
        processor.save_processed_data(X_reduced, y, [f"feature_{i}" for i in range(X_reduced.shape[1])])
        
        print("\nData processing completed successfully!")
        print(f"Final data shape: {X_reduced.shape}")
        print(f"Number of classes: {len(np.unique(y))}")
        
    except Exception as e:
        print(f"Error during data processing: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
