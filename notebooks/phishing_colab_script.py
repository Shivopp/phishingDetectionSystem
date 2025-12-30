"""
INTELLIGENT PHISHING DETECTION SYSTEM
Google Colab Implementation with TensorFlow Integration
"""

# ============================================
# SECTION 1: ENVIRONMENT SETUP (GOOGLE COLAB)
# ============================================

# Install required packages
# !pip install -q scikit-learn pandas numpy matplotlib seaborn
# !pip install -q tensorflow keras
# !pip install -q streamlit
# !pip install -q tldextract python-whois

# Import essential libraries
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from urllib.parse import urlparse
import re
import tldextract
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
import warnings
warnings.filterwarnings('ignore')

print("TensorFlow Version:", tf.__version__)
print("GPU Available:", tf.config.list_physical_devices('GPU'))

# ============================================
# SECTION 2: DATA LOADING
# ============================================

def create_sample_dataset():
    """Create sample phishing dataset"""
    urls = [
        'https://www.google.com',
        'http://login-paypal-verify.xyz/account',
        'https://github.com/security',
        'http://secure-bankofamerica.net.verify.login.com',
        'https://amazon.com/products',
        'http://microsoft-account-recovery.tk/login',
        'https://linkedin.com/jobs',
        'http://apple-id-unlock.ml/verify',
        'https://stackoverflow.com/questions',
        'http://facebook-security-check.ga/account',
    ] * 100
    
    labels = [0, 1, 0, 1, 0, 1, 0, 1, 0, 1] * 100
    
    df = pd.DataFrame({'url': urls, 'label': labels})
    return df

df = create_sample_dataset()
print(f"Dataset loaded: {len(df)} URLs")
print(f"Phishing: {df['label'].sum()}, Legitimate: {len(df) - df['label'].sum()}")

# ============================================
# SECTION 3: FEATURE EXTRACTION
# ============================================

import math

def extract_url_features(url):
    """Extract 17 features from URL"""
    features = {}
    
    try:
        parsed = urlparse(url)
        ext = tldextract.extract(url)
        
        features['url_length'] = len(url)
        features['domain_length'] = len(parsed.netloc)
        features['path_length'] = len(parsed.path)
        features['dots_count'] = url.count('.')
        features['hyphen_count'] = url.count('-')
        features['underline_count'] = url.count('_')
        features['slash_count'] = url.count('/')
        features['question_count'] = url.count('?')
        features['has_https'] = 1 if parsed.scheme == 'https' else 0
        features['has_ip'] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed.netloc) else 0
        features['has_at'] = 1 if '@' in url else 0
        
        suspicious_keywords = ['login', 'verify', 'account', 'update', 'secure']
        features['suspicious_keywords'] = sum(1 for kw in suspicious_keywords if kw in url.lower())
        features['subdomain_count'] = len(ext.subdomain.split('.')) if ext.subdomain else 0
        features['tld_length'] = len(ext.suffix)
        features['suspicious_tld'] = 1 if any(tld in url.lower() for tld in ['.tk', '.ml', '.ga']) else 0
        
        prob = [float(url.count(c)) / len(url) for c in dict.fromkeys(list(url))]
        features['url_entropy'] = -sum([p * math.log(p) / math.log(2.0) for p in prob])
        
        digits = sum(c.isdigit() for c in url)
        letters = sum(c.isalpha() for c in url)
        features['digit_ratio'] = digits / letters if letters > 0 else 0
        
    except:
        features = {k: 0 for k in ['url_length', 'domain_length', 'path_length', 
                   'dots_count', 'hyphen_count', 'underline_count', 'slash_count',
                   'question_count', 'has_https', 'has_ip', 'has_at',
                   'suspicious_keywords', 'subdomain_count', 'tld_length',
                   'suspicious_tld', 'url_entropy', 'digit_ratio']}
    
    return features

# Extract features
print("Extracting features...")
features_list = []
for idx, row in df.iterrows():
    features = extract_url_features(row['url'])
    features['label'] = row['label']
    features_list.append(features)

features_df = pd.DataFrame(features_list)
print("Feature extraction complete!")

# ============================================
# SECTION 4: TRAIN-TEST SPLIT
# ============================================

X = features_df.drop('label', axis=1)
y = features_df['label']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print(f"Training: {len(X_train)}, Test: {len(X_test)}")

# ============================================
# SECTION 5: RANDOM FOREST
# ============================================

print("\nTraining Random Forest...")
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)

y_pred_rf = rf_model.predict(X_test)
rf_accuracy = accuracy_score(y_test, y_pred_rf)
print(f"Random Forest Accuracy: {rf_accuracy:.4f}")

# ============================================
# SECTION 6: TENSORFLOW NEURAL NETWORK
# ============================================

print("\nBuilding TensorFlow Neural Network...")
tf_model = keras.Sequential([
    layers.Input(shape=(X_train_scaled.shape[1],)),
    layers.Dense(64, activation='relu'),
    layers.BatchNormalization(),
    layers.Dropout(0.3),
    layers.Dense(32, activation='relu'),
    layers.Dropout(0.2),
    layers.Dense(16, activation='relu'),
    layers.Dense(1, activation='sigmoid')
])

tf_model.compile(
    optimizer='adam',
    loss='binary_crossentropy',
    metrics=['accuracy']
)

history = tf_model.fit(
    X_train_scaled, y_train,
    epochs=30,
    batch_size=32,
    validation_split=0.2,
    verbose=1
)

y_pred_tf = (tf_model.predict(X_test_scaled) > 0.5).astype(int)
tf_accuracy = accuracy_score(y_test, y_pred_tf)
print(f"TensorFlow Accuracy: {tf_accuracy:.4f}")

# ============================================
# SECTION 7: SAVE MODELS
# ============================================

import pickle

# Save Random Forest
with open('random_forest_model.pkl', 'wb') as f:
    pickle.dump(rf_model, f)

# Save TensorFlow
tf_model.save('tensorflow_model.h5')

# Save Scaler
with open('feature_scaler.pkl', 'wb') as f:
    pickle.dump(scaler, f)

print("\n✅ All models saved successfully!")