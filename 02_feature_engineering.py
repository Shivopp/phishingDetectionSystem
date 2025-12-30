"""
Advanced Feature Engineering for Phishing Detection
Extracts 20+ URL and domain-based features for ML model training.
"""

import pandas as pd
import numpy as np
from urllib.parse import urlparse
import re
import socket
import whois
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

class FeatureExtractor:
    """Extract advanced features from URLs for phishing detection"""
    
    def __init__(self, df):
        self.df = df.copy()
        self.features = pd.DataFrame()
    
    def extract_all_features(self):
        """Extract all URL-based features"""
        print("Extracting advanced URL features...")
        
        self.features['url'] = self.df['url']
        self.features['label'] = self.df['label']
        
        # Basic URL features
        self.features['url_length'] = self.df['url'].apply(self._url_length)
        self.features['domain_length'] = self.df['url'].apply(self._domain_length)
        self.features['num_dots'] = self.df['url'].apply(lambda x: x.count('.'))
        self.features['num_hyphens'] = self.df['url'].apply(lambda x: x.count('-'))
        self.features['num_slashes'] = self.df['url'].apply(lambda x: x.count('/'))
        self.features['num_underscores'] = self.df['url'].apply(lambda x: x.count('_'))
        self.features['num_at_symbol'] = self.df['url'].apply(lambda x: x.count('@'))
        self.features['num_question_marks'] = self.df['url'].apply(lambda x: x.count('?'))
        
        # Protocol and security features
        self.features['has_https'] = self.df['url'].apply(lambda x: 1 if x.startswith('https') else 0)
        self.features['has_http'] = self.df['url'].apply(lambda x: 1 if x.startswith('http') else 0)
        
        # Domain features
        self.features['has_ip_address'] = self.df['url'].apply(self._has_ip_address)
        self.features['domain_has_at'] = self.df['url'].apply(self._domain_has_at)
        
        # Suspicious keyword detection
        self.features['has_suspicious_keywords'] = self.df['url'].apply(self._has_suspicious_keywords)
        self.features['has_login_keyword'] = self.df['url'].apply(lambda x: 1 if 'login' in x.lower() else 0)
        self.features['has_verify_keyword'] = self.df['url'].apply(lambda x: 1 if 'verify' in x.lower() else 0)
        self.features['has_confirm_keyword'] = self.df['url'].apply(lambda x: 1 if 'confirm' in x.lower() else 0)
        self.features['has_secure_keyword'] = self.df['url'].apply(lambda x: 1 if 'secure' in x.lower() else 0)
        self.features['has_bank_keyword'] = self.df['url'].apply(lambda x: 1 if 'bank' in x.lower() else 0)
        self.features['has_update_keyword'] = self.df['url'].apply(lambda x: 1 if 'update' in x.lower() else 0)
        
        # Character pattern features
        self.features['num_digits'] = self.df['url'].apply(lambda x: sum(c.isdigit() for c in x))
        self.features['num_special_chars'] = self.df['url'].apply(self._count_special_chars)
        self.features['entropy_score'] = self.df['url'].apply(self._calculate_entropy)
        
        # Subdomain features
        self.features['num_subdomains'] = self.df['url'].apply(self._count_subdomains)
        
        print(f"Extracted {len(self.features.columns) - 2} features for each URL")
        
        return self.features
    
    def _url_length(self, url):
        """Feature: Length of URL"""
        return len(url)
    
    def _domain_length(self, url):
        """Feature: Length of domain"""
        try:
            parsed = urlparse(url)
            return len(parsed.netloc)
        except:
            return 0
    
    def _has_ip_address(self, url):
        """Feature: URL uses IP address instead of domain"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
                return 1
            return 0
        except:
            return 0
    
    def _domain_has_at(self, url):
        """Feature: Domain contains '@' symbol (common in phishing)"""
        try:
            parsed = urlparse(url)
            if '@' in parsed.netloc:
                return 1
            return 0
        except:
            return 0
    
    def _has_suspicious_keywords(self, url):
        """Feature: URL contains multiple suspicious keywords"""
        suspicious_keywords = [
            'login', 'verify', 'confirm', 'account', 'secure', 'bank',
            'update', 'alert', 'action-required', 'activate', 'suspended'
        ]
        url_lower = url.lower()
        count = sum(1 for keyword in suspicious_keywords if keyword in url_lower)
        return 1 if count >= 2 else 0
    
    def _count_special_chars(self, url):
        """Feature: Number of special characters"""
        special_chars = set('!@#$%^&*()_+-=[]{}|;:,.<>?/~`')
        return sum(1 for char in url if char in special_chars)
    
    def _calculate_entropy(self, url):
        """Feature: Shannon entropy of URL (randomness indicator)"""
        if not url:
            return 0
        
        entropy = 0
        for char in set(url):
            freq = url.count(char) / len(url)
            entropy -= freq * np.log2(freq)
        
        return entropy
    
    def _count_subdomains(self, url):
        """Feature: Number of subdomains"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            # Count dots in domain (minus 1 for TLD)
            return domain.count('.') - 1
        except:
            return 0
    
    def get_feature_statistics(self):
        """Display feature statistics"""
        print("\n" + "="*60)
        print("FEATURE STATISTICS")
        print("="*60)
        
        # Feature importance by class
        print("\nFeature Comparison (Legitimate vs Phishing):\n")
        numeric_features = self.features.select_dtypes(include=[np.number]).columns
        
        for feature in numeric_features:
            if feature == 'label':
                continue
            legit_mean = self.features[self.features['label'] == 0][feature].mean()
            phishing_mean = self.features[self.features['label'] == 1][feature].mean()
            
            print(f"{feature:30s} | Legitimate: {legit_mean:8.2f} | Phishing: {phishing_mean:8.2f}")
        
        return self.features

# Main execution
if __name__ == "__main__":
    import os
    os.makedirs('output', exist_ok=True)
    
    # Load cleaned dataset
    df = pd.read_csv('data/phishing_dataset_clean.csv')
    
    # Extract features
    extractor = FeatureExtractor(df)
    features_df = extractor.extract_all_features()
    feature_stats = extractor.get_feature_statistics()
    
    # Save featured dataset
    features_df.to_csv('data/phishing_features.csv', index=False)
    print("\nFeatured dataset saved to: data/phishing_features.csv")
