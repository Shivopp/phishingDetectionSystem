"""
PHISHING DETECTION - MACHINE LEARNING MODELS
Complete Model Training & Evaluation Pipeline
Random Forest + TensorFlow Neural Network
================================================
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, precision_score, recall_score, 
                             f1_score, confusion_matrix, classification_report,
                             roc_curve, auc, roc_auc_score)
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, callbacks
import pickle
import time
import warnings
import os

warnings.filterwarnings('ignore')


def create_sample_dataset():
    """Create sample phishing dataset for training"""
    np.random.seed(42)
    n_samples = 5000
    
    print("Creating synthetic phishing dataset...")
    
    # Generate features
    data = {
        'url_length': np.random.randint(10, 200, n_samples),
        'num_dots': np.random.randint(0, 10, n_samples),
        'num_hyphens': np.random.randint(0, 5, n_samples),
        'num_underscores': np.random.randint(0, 3, n_samples),
        'num_slashes': np.random.randint(1, 8, n_samples),
        'num_questionmarks': np.random.randint(0, 3, n_samples),
        'num_equal': np.random.randint(0, 5, n_samples),
        'num_at': np.random.randint(0, 2, n_samples),
        'num_ampersand': np.random.randint(0, 4, n_samples),
        'num_digits': np.random.randint(0, 30, n_samples),
        'has_ip': np.random.randint(0, 2, n_samples),
        'has_https': np.random.randint(0, 2, n_samples),
        'domain_age': np.random.randint(0, 3650, n_samples),
        'ssl_cert': np.random.randint(0, 2, n_samples),
        'num_subdomains': np.random.randint(0, 5, n_samples),
        'entropy': np.random.uniform(2, 5, n_samples),
    }
    
    df = pd.DataFrame(data)
    
    # Create labels (phishing = 1, legitimate = 0)
    df['label'] = 0
    df.loc[(df['url_length'] > 75) | (df['num_dots'] > 4) | (df['has_ip'] == 1) | 
           (df['has_https'] == 0) | (df['domain_age'] < 30), 'label'] = 1
    
    # Add noise for realism
    noise_idx = np.random.choice(df.index, size=int(0.1 * len(df)), replace=False)
    df.loc[noise_idx, 'label'] = 1 - df.loc[noise_idx, 'label']
    
    return df


def prepare_data():
    """Load or create dataset and prepare for training"""
    print("=" * 70)
    print("DATA PREPARATION")
    print("=" * 70)
    
    # Check if processed data exists
    if os.path.exists('processed_data.pkl'):
        print("\n📂 Loading preprocessed data...")
        with open('processed_data.pkl', 'rb') as f:
            data = pickle.load(f)
        
        X_train = data['X_train']
        X_test = data['X_test']
        y_train = data['y_train']
        y_test = data['y_test']
        X_train_scaled = data['X_train_scaled']
        X_test_scaled = data['X_test_scaled']
        scaler = data['scaler']
        feature_names = data['feature_names']
        
    else:
        print("\n📊 Creating new dataset...")
        df = create_sample_dataset()
        
        print(f"   Dataset size: {len(df)} samples")
        print(f"   Phishing: {sum(df['label'] == 1)}, Legitimate: {sum(df['label'] == 0)}")
        
        # Prepare features and labels
        X = df.drop('label', axis=1)
        y = df['label']
        feature_names = X.columns.tolist()
        
        # Split data
        print("\n🔀 Splitting data (80% train, 20% test)...")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        print("📏 Scaling features...")
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Save processed data
        data = {
            'X_train': X_train,
            'X_test': X_test,
            'y_train': y_train,
            'y_test': y_test,
            'X_train_scaled': X_train_scaled,
            'X_test_scaled': X_test_scaled,
            'scaler': scaler,
            'feature_names': feature_names
        }
        with open('processed_data.pkl', 'wb') as f:
            pickle.dump(data, f)
        print("✓ Processed data saved")
    
    print(f"\n✓ Training samples: {len(X_train)}")
    print(f"✓ Test samples: {len(X_test)}")
    print(f"✓ Features: {len(feature_names)}")
    
    return X_train, X_test, y_train, y_test, X_train_scaled, X_test_scaled, scaler, feature_names


def train_random_forest(X_train, y_train):
    """Train Random Forest Classifier"""
    print("\n" + "=" * 70)
    print("MODEL 1: RANDOM FOREST CLASSIFIER")
    print("=" * 70)
    
    print("\n📊 Why Random Forest?")
    print("  • Handles non-linear relationships")
    print("  • Feature importance interpretation")
    print("  • Resistant to overfitting")
    print("  • No feature scaling required")
    print("  • Excellent for tabular data")
    
    print("\n🔄 Training Random Forest...")
    start_time = time.time()
    
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        verbose=1
    )
    
    rf_model.fit(X_train, y_train)
    training_time = time.time() - start_time
    
    print(f"✓ Training completed in {training_time:.2f} seconds")
    
    return rf_model, training_time


def evaluate_random_forest(rf_model, X_test, y_test, feature_names):
    """Evaluate Random Forest model"""
    print("\n" + "=" * 70)
    print("RANDOM FOREST EVALUATION METRICS")
    print("=" * 70)
    
    # Predictions
    y_pred_rf = rf_model.predict(X_test)
    y_pred_proba_rf = rf_model.predict_proba(X_test)[:, 1]
    
    # Calculate metrics
    rf_accuracy = accuracy_score(y_test, y_pred_rf)
    rf_precision = precision_score(y_test, y_pred_rf)
    rf_recall = recall_score(y_test, y_pred_rf)
    rf_f1 = f1_score(y_test, y_pred_rf)
    rf_auc = roc_auc_score(y_test, y_pred_proba_rf)
    
    print(f"\n📈 PERFORMANCE METRICS:")
    print(f"  Accuracy:  {rf_accuracy:.4f} ({rf_accuracy*100:.2f}%)")
    print(f"  Precision: {rf_precision:.4f} ({rf_precision*100:.2f}%)")
    print(f"  Recall:    {rf_recall:.4f} ({rf_recall*100:.2f}%)")
    print(f"  F1-Score:  {rf_f1:.4f}")
    print(f"  ROC-AUC:   {rf_auc:.4f}")
    
    # Confusion Matrix
    cm_rf = confusion_matrix(y_test, y_pred_rf)
    print(f"\n📊 CONFUSION MATRIX:")
    print(f"  True Negatives:  {cm_rf[0,0]:4d} (Correctly identified legitimate)")
    print(f"  False Positives: {cm_rf[0,1]:4d} (Legitimate marked as phishing)")
    print(f"  False Negatives: {cm_rf[1,0]:4d} (Phishing marked as legitimate) ⚠️")
    print(f"  True Positives:  {cm_rf[1,1]:4d} (Correctly identified phishing)")
    
    # Classification Report
    print(f"\n📋 DETAILED CLASSIFICATION REPORT:")
    print(classification_report(y_test, y_pred_rf, 
                               target_names=['Legitimate', 'Phishing']))
    
    # Feature Importance
    feature_importance = pd.DataFrame({
        'feature': feature_names,
        'importance': rf_model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print(f"\n🔑 TOP 10 MOST IMPORTANT FEATURES:")
    for idx, row in feature_importance.head(10).iterrows():
        print(f"  {row['feature']:20s}: {row['importance']:.4f}")
    
    metrics = {
        'accuracy': rf_accuracy,
        'precision': rf_precision,
        'recall': rf_recall,
        'f1': rf_f1,
        'auc': rf_auc,
        'predictions': y_pred_rf,
        'probabilities': y_pred_proba_rf,
        'confusion_matrix': cm_rf,
        'feature_importance': feature_importance
    }
    
    return metrics


def train_tensorflow_model(X_train_scaled, y_train):
    """Train TensorFlow Neural Network"""
    print("\n" + "=" * 70)
    print("MODEL 2: TENSORFLOW NEURAL NETWORK")
    print("=" * 70)
    
    print("\n🧠 Why TensorFlow Deep Learning?")
    print("  • Learns complex non-linear patterns")
    print("  • Google's production-ready ML framework")
    print("  • GPU acceleration support")
    print("  • Automatic feature learning")
    print("  • State-of-the-art performance")
    
    print("\n🏗️  Building Neural Network Architecture...")
    
    tf_model = keras.Sequential([
        layers.Input(shape=(X_train_scaled.shape[1],)),
        layers.Dense(64, activation='relu', name='hidden_layer_1'),
        layers.BatchNormalization(),
        layers.Dropout(0.3),
        layers.Dense(32, activation='relu', name='hidden_layer_2'),
        layers.BatchNormalization(),
        layers.Dropout(0.2),
        layers.Dense(16, activation='relu', name='hidden_layer_3'),
        layers.Dropout(0.1),
        layers.Dense(1, activation='sigmoid', name='output_layer')
    ])
    
    print("\n📐 NEURAL NETWORK ARCHITECTURE:")
    tf_model.summary()
    
    # Compile model
    tf_model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=0.001),
        loss='binary_crossentropy',
        metrics=['accuracy', keras.metrics.Precision(), keras.metrics.Recall()]
    )
    
    # Callbacks
    early_stopping = callbacks.EarlyStopping(
        monitor='val_loss',
        patience=10,
        restore_best_weights=True,
        verbose=1
    )
    
    reduce_lr = callbacks.ReduceLROnPlateau(
        monitor='val_loss',
        factor=0.5,
        patience=5,
        min_lr=0.00001,
        verbose=1
    )
    
    print("\n🔄 Training TensorFlow Neural Network...")
    start_time = time.time()
    
    history = tf_model.fit(
        X_train_scaled, y_train,
        epochs=50,
        batch_size=32,
        validation_split=0.2,
        callbacks=[early_stopping, reduce_lr],
        verbose=1
    )
    
    training_time = time.time() - start_time
    print(f"\n✓ Training completed in {training_time:.2f} seconds")
    
    return tf_model, history, training_time


def evaluate_tensorflow_model(tf_model, X_test_scaled, y_test):
    """Evaluate TensorFlow model"""
    print("\n" + "=" * 70)
    print("TENSORFLOW NEURAL NETWORK EVALUATION")
    print("=" * 70)
    
    # Predictions
    y_pred_proba_tf = tf_model.predict(X_test_scaled, verbose=0).flatten()
    y_pred_tf = (y_pred_proba_tf > 0.5).astype(int)
    
    # Calculate metrics
    tf_accuracy = accuracy_score(y_test, y_pred_tf)
    tf_precision = precision_score(y_test, y_pred_tf)
    tf_recall = recall_score(y_test, y_pred_tf)
    tf_f1 = f1_score(y_test, y_pred_tf)
    tf_auc = roc_auc_score(y_test, y_pred_proba_tf)
    
    print(f"\n📈 PERFORMANCE METRICS:")
    print(f"  Accuracy:  {tf_accuracy:.4f} ({tf_accuracy*100:.2f}%)")
    print(f"  Precision: {tf_precision:.4f} ({tf_precision*100:.2f}%)")
    print(f"  Recall:    {tf_recall:.4f} ({tf_recall*100:.2f}%)")
    print(f"  F1-Score:  {tf_f1:.4f}")
    print(f"  ROC-AUC:   {tf_auc:.4f}")
    
    # Confusion Matrix
    cm_tf = confusion_matrix(y_test, y_pred_tf)
    print(f"\n📊 CONFUSION MATRIX:")
    print(f"  True Negatives:  {cm_tf[0,0]:4d}")
    print(f"  False Positives: {cm_tf[0,1]:4d}")
    print(f"  False Negatives: {cm_tf[1,0]:4d} ⚠️")
    print(f"  True Positives:  {cm_tf[1,1]:4d}")
    
    metrics = {
        'accuracy': tf_accuracy,
        'precision': tf_precision,
        'recall': tf_recall,
        'f1': tf_f1,
        'auc': tf_auc,
        'predictions': y_pred_tf,
        'probabilities': y_pred_proba_tf,
        'confusion_matrix': cm_tf
    }
    
    return metrics


def compare_models(rf_metrics, tf_metrics, rf_time, tf_time):
    """Compare both models"""
    print("\n" + "=" * 70)
    print("MODEL COMPARISON: RANDOM FOREST vs TENSORFLOW")
    print("=" * 70)
    
    comparison = pd.DataFrame({
        'Metric': ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'ROC-AUC', 'Training Time'],
        'Random Forest': [
            rf_metrics['accuracy'], rf_metrics['precision'], 
            rf_metrics['recall'], rf_metrics['f1'], 
            rf_metrics['auc'], rf_time
        ],
        'TensorFlow NN': [
            tf_metrics['accuracy'], tf_metrics['precision'], 
            tf_metrics['recall'], tf_metrics['f1'], 
            tf_metrics['auc'], tf_time
        ]
    })
    
    print("\n", comparison.to_string(index=False))
    
    # Winner determination
    rf_score = (rf_metrics['accuracy'] + rf_metrics['f1'] + rf_metrics['auc']) / 3
    tf_score = (tf_metrics['accuracy'] + tf_metrics['f1'] + tf_metrics['auc']) / 3
    
    print(f"\n🏆 OVERALL PERFORMANCE:")
    print(f"  Random Forest Score: {rf_score:.4f}")
    print(f"  TensorFlow Score:    {tf_score:.4f}")
    if rf_score > tf_score:
        print("  Winner: Random Forest ✓")
    else:
        print("  Winner: TensorFlow ✓")


def create_visualizations(rf_metrics, tf_metrics, history, y_test):
    """Generate comprehensive visualizations"""
    print("\n" + "=" * 70)
    print("GENERATING VISUALIZATIONS")
    print("=" * 70)
    
    fig = plt.figure(figsize=(18, 12))
    
    # 1. Confusion Matrices
    plt.subplot(3, 3, 1)
    sns.heatmap(rf_metrics['confusion_matrix'], annot=True, fmt='d', cmap='Blues', cbar=False)
    plt.title('Random Forest - Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    
    plt.subplot(3, 3, 2)
    sns.heatmap(tf_metrics['confusion_matrix'], annot=True, fmt='d', cmap='Greens', cbar=False)
    plt.title('TensorFlow - Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    
    # 2. ROC Curves
    plt.subplot(3, 3, 3)
    fpr_rf, tpr_rf, _ = roc_curve(y_test, rf_metrics['probabilities'])
    fpr_tf, tpr_tf, _ = roc_curve(y_test, tf_metrics['probabilities'])
    plt.plot(fpr_rf, tpr_rf, label=f'Random Forest (AUC={rf_metrics["auc"]:.3f})', linewidth=2)
    plt.plot(fpr_tf, tpr_tf, label=f'TensorFlow (AUC={tf_metrics["auc"]:.3f})', linewidth=2)
    plt.plot([0, 1], [0, 1], 'k--', label='Random Guess')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('ROC Curves Comparison')
    plt.legend()
    plt.grid(True, alpha=0.3)
    
    # 3. Feature Importance
    plt.subplot(3, 3, 4)
    top_features = rf_metrics['feature_importance'].head(10)
    plt.barh(range(len(top_features)), top_features['importance'], color='steelblue')
    plt.yticks(range(len(top_features)), top_features['feature'])
    plt.xlabel('Importance Score')
    plt.title('Top 10 Feature Importance (RF)')
    plt.gca().invert_yaxis()
    
    # 4. Training History
    plt.subplot(3, 3, 5)
    plt.plot(history.history['accuracy'], label='Train Accuracy', linewidth=2)
    plt.plot(history.history['val_accuracy'], label='Val Accuracy', linewidth=2)
    plt.xlabel('Epoch')
    plt.ylabel('Accuracy')
    plt.title('TensorFlow Training History')
    plt.legend()
    plt.grid(True, alpha=0.3)
    
    plt.subplot(3, 3, 6)
    plt.plot(history.history['loss'], label='Train Loss', linewidth=2)
    plt.plot(history.history['val_loss'], label='Val Loss', linewidth=2)
    plt.xlabel('Epoch')
    plt.ylabel('Loss')
    plt.title('TensorFlow Loss History')
    plt.legend()
    plt.grid(True, alpha=0.3)
    
    # 5. Metrics Comparison
    plt.subplot(3, 3, 7)
    metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
    rf_values = [rf_metrics['accuracy'], rf_metrics['precision'], 
                 rf_metrics['recall'], rf_metrics['f1']]
    tf_values = [tf_metrics['accuracy'], tf_metrics['precision'], 
                 tf_metrics['recall'], tf_metrics['f1']]
    x = np.arange(len(metrics))
    width = 0.35
    plt.bar(x - width/2, rf_values, width, label='Random Forest', color='steelblue')
    plt.bar(x + width/2, tf_values, width, label='TensorFlow', color='forestgreen')
    plt.ylabel('Score')
    plt.title('Model Performance Comparison')
    plt.xticks(x, metrics, rotation=45)
    plt.legend()
    plt.ylim(0.8, 1.0)
    plt.grid(True, alpha=0.3, axis='y')
    
    # 6. Prediction Distribution
    plt.subplot(3, 3, 8)
    plt.hist(rf_metrics['probabilities'][y_test == 0], bins=30, alpha=0.5, 
             label='Legitimate', color='green')
    plt.hist(rf_metrics['probabilities'][y_test == 1], bins=30, alpha=0.5, 
             label='Phishing', color='red')
    plt.xlabel('Prediction Probability')
    plt.ylabel('Frequency')
    plt.title('RF Prediction Distribution')
    plt.legend()
    plt.axvline(x=0.5, color='black', linestyle='--')
    
    plt.subplot(3, 3, 9)
    plt.hist(tf_metrics['probabilities'][y_test == 0], bins=30, alpha=0.5, 
             label='Legitimate', color='green')
    plt.hist(tf_metrics['probabilities'][y_test == 1], bins=30, alpha=0.5, 
             label='Phishing', color='red')
    plt.xlabel('Prediction Probability')
    plt.ylabel('Frequency')
    plt.title('TF Prediction Distribution')
    plt.legend()
    plt.axvline(x=0.5, color='black', linestyle='--')
    
    plt.tight_layout()
    plt.savefig('model_evaluation_complete.png', dpi=300, bbox_inches='tight')
    print("✓ Comprehensive evaluation visualization saved: model_evaluation_complete.png")


def save_models(rf_model, tf_model, scaler):
    """Save trained models"""
    print("\n" + "=" * 70)
    print("SAVING TRAINED MODELS")
    print("=" * 70)
    
    # Save Random Forest
    with open('random_forest_model.pkl', 'wb') as f:
        pickle.dump(rf_model, f)
    print("✓ Random Forest model saved: random_forest_model.pkl")
    
    # Save TensorFlow model
    tf_model.save('tensorflow_model.h5')
    print("✓ TensorFlow model saved: tensorflow_model.h5")
    
    # Save scaler
    with open('feature_scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)
    print("✓ Feature scaler saved: feature_scaler.pkl")


def main():
    """Main training pipeline"""
    print("=" * 70)
    print("PHISHING DETECTION - COMPLETE MODEL TRAINING PIPELINE")
    print("=" * 70)
    
    # Step 1: Prepare data
    X_train, X_test, y_train, y_test, X_train_scaled, X_test_scaled, scaler, feature_names = prepare_data()
    
    # Step 2: Train Random Forest
    rf_model, rf_time = train_random_forest(X_train, y_train)
    
    # Step 3: Evaluate Random Forest
    rf_metrics = evaluate_random_forest(rf_model, X_test, y_test, feature_names)
    
    # Step 4: Train TensorFlow
    tf_model, history, tf_time = train_tensorflow_model(X_train_scaled, y_train)
    
    # Step 5: Evaluate TensorFlow
    tf_metrics = evaluate_tensorflow_model(tf_model, X_test_scaled, y_test)
    
    # Step 6: Compare models
    compare_models(rf_metrics, tf_metrics, rf_time, tf_time)
    
    # Step 7: Create visualizations
    create_visualizations(rf_metrics, tf_metrics, history, y_test)
    
    # Step 8: Save models
    save_models(rf_model, tf_model, scaler)
    
    print("\n" + "=" * 70)
    print("✓ MODEL TRAINING COMPLETE!")
    print("=" * 70)
    print("\nNext Steps:")
    print("  1. Run 'python app.py' to start the web application")
    print("  2. Test the models with real URLs")
    print("  3. Integrate with Google Safe Browsing API")
    print("=" * 70)


if __name__ == "__main__":
    main()