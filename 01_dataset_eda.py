"""
Intelligent Phishing Detection System - Dataset & Exploratory Data Analysis
This module handles data loading, cleaning, and exploratory analysis using real-world phishing datasets.

Data Sources:
- Kaggle Phishing Website Dataset
- PhishTank Database
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from urllib.parse import urlparse
import requests
import warnings
warnings.filterwarnings('ignore')

# Set visualization style
sns.set_style("darkgrid")
plt.rcParams['figure.figsize'] = (12, 6)

class DatasetManager:
    """Manages phishing dataset loading and preprocessing"""
    
    def __init__(self):
        self.df = None
        self.dataset_info = {
            'sources': ['Kaggle Phishing Website Dataset', 'PhishTank'],
            'columns': ['url', 'label'],  # 0 = legitimate, 1 = phishing
            'total_samples': 0,
            'legitimate_count': 0,
            'phishing_count': 0
        }
    
    def load_kaggle_dataset(self):
        """
        Load phishing dataset from Kaggle.
        In production, download from: https://www.kaggle.com/datasets/shashwatwork/phishing-dataset-for-machine-learning
        For demo purposes, we'll create a representative sample.
        """
        print("Loading Kaggle Phishing Dataset...")
        
        # Sample legitimate URLs
        legitimate_urls = [
            'https://www.google.com',
            'https://www.facebook.com/login',
            'https://www.amazon.com/ap/signin',
            'https://www.twitter.com/login',
            'https://www.github.com/login',
            'https://www.linkedin.com/login',
            'https://www.stackoverflow.com/users/login',
            'https://www.spotify.com/login',
            'https://www.netflix.com/login',
            'https://mail.google.com',
            'https://www.wikipedia.org',
            'https://www.reddit.com',
            'https://www.youtube.com',
            'https://www.instagram.com/accounts/login',
            'https://www.microsoft.com',
        ]
        
        # Sample phishing URLs
        phishing_urls = [
            'https://www.g00gle.com/login',
            'https://www.goog1e-account.com/verify',
            'https://secure-amazon-verify.xyz/signin',
            'https://paypal-update-confirm.ru/account',
            'https://apple-id-verify.tk/login',
            'https://facebook-security-center.online/confirm',
            'http://bankofamerica-verify.ml/signin',
            'https://www-amazon-com.verify-account.click/ap/signin',
            'https://207.21.4.53/login',  # IP address instead of domain
            'https://gogle.com',  # Typosquatting
            'https://bitc0in-wallet-verify.ru/secure',
            'https://chase-login-secure.xyz/auth',
            'https://dropbox-verify-identity.ml/login',
            'https://uber-account-confirm.ru/signin',
            'https://airbnb-update-security.online/login',
        ]
        
        # Create dataset
        urls = legitimate_urls + phishing_urls
        labels = [0] * len(legitimate_urls) + [1] * len(phishing_urls)
        
        self.df = pd.DataFrame({
            'url': urls,
            'label': labels
        })
        
        self.dataset_info['total_samples'] = len(self.df)
        self.dataset_info['legitimate_count'] = (self.df['label'] == 0).sum()
        self.dataset_info['phishing_count'] = (self.df['label'] == 1).sum()
        
        print(f"Dataset loaded successfully!")
        print(f"Total samples: {self.dataset_info['total_samples']}")
        print(f"Legitimate: {self.dataset_info['legitimate_count']}")
        print(f"Phishing: {self.dataset_info['phishing_count']}")
        
        return self.df
    
    def data_cleaning(self):
        """Clean and preprocess the dataset"""
        print("\nCleaning and preprocessing data...")
        
        # Remove duplicates
        initial_count = len(self.df)
        self.df = self.df.drop_duplicates(subset=['url'])
        removed_count = initial_count - len(self.df)
        print(f"Removed {removed_count} duplicate URLs")
        
        # Remove invalid URLs
        self.df = self.df[self.df['url'].str.startswith(('http://', 'https://'))]
        
        # Convert labels to int
        self.df['label'] = self.df['label'].astype(int)
        
        print(f"Clean dataset size: {len(self.df)} samples")
        
        return self.df
    
    def exploratory_data_analysis(self):
        """Perform comprehensive EDA"""
        print("\n" + "="*60)
        print("EXPLORATORY DATA ANALYSIS (EDA)")
        print("="*60)
        
        # Class distribution
        print("\n1. CLASS DISTRIBUTION:")
        print(self.df['label'].value_counts())
        print(f"Class Balance Ratio: {(self.df['label'] == 1).sum() / (self.df['label'] == 0).sum():.2%} phishing")
        
        # Plot class distribution
        fig, axes = plt.subplots(1, 2, figsize=(12, 4))
        
        self.df['label'].value_counts().plot(kind='bar', ax=axes[0], color=['green', 'red'])
        axes[0].set_title('URL Classification Distribution')
        axes[0].set_xlabel('Label (0=Legitimate, 1=Phishing)')
        axes[0].set_ylabel('Count')
        
        self.df['label'].value_counts().plot(kind='pie', ax=axes[1], autopct='%1.1f%%', colors=['green', 'red'])
        axes[1].set_title('Phishing vs Legitimate URLs')
        axes[1].set_ylabel('')
        
        plt.tight_layout()
        plt.savefig('output/01_class_distribution.png', dpi=300, bbox_inches='tight')
        print("\nSaved: output/01_class_distribution.png")
        
        # URL statistics
        print("\n2. URL STATISTICS:")
        self.df['url_length'] = self.df['url'].str.len()
        print(self.df['url_length'].describe())
        
        # Plot URL length distribution
        fig, ax = plt.subplots(figsize=(12, 5))
        for label in [0, 1]:
            data = self.df[self.df['label'] == label]['url_length']
            ax.hist(data, alpha=0.6, label=f"{'Legitimate' if label == 0 else 'Phishing'}", bins=30)
        ax.set_xlabel('URL Length')
        ax.set_ylabel('Frequency')
        ax.set_title('URL Length Distribution by Class')
        ax.legend()
        plt.tight_layout()
        plt.savefig('output/02_url_length_distribution.png', dpi=300, bbox_inches='tight')
        print("\nSaved: output/02_url_length_distribution.png")
        
        print("\nEDA Complete. Statistics saved to output/")

# Main execution
if __name__ == "__main__":
    import os
    os.makedirs('output', exist_ok=True)
    
    # Initialize and load dataset
    dm = DatasetManager()
    df = dm.load_kaggle_dataset()
    
    # Data cleaning
    df_clean = dm.data_cleaning()
    
    # EDA
    dm.exploratory_data_analysis()
    
    # Save cleaned dataset
    df_clean.to_csv('data/phishing_dataset_clean.csv', index=False)
    print("\nCleaned dataset saved to: data/phishing_dataset_clean.csv")
