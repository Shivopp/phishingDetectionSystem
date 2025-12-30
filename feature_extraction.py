import re
from urllib.parse import urlparse
import tldextract
import math

def extract_url_features(url):
    """Extract 17+ advanced features from URL"""
    features = {}
    
    try:
        parsed = urlparse(url)
        ext = tldextract.extract(url)
        
        # Basic features
        features['url_length'] = len(url)
        features['domain_length'] = len(parsed.netloc)
        features['path_length'] = len(parsed.path)
        
        # Character counts
        features['dots_count'] = url.count('.')
        features['hyphen_count'] = url.count('-')
        features['underline_count'] = url.count('_')
        features['slash_count'] = url.count('/')
        features['question_count'] = url.count('?')
        
        # Security indicators
        features['has_https'] = 1 if parsed.scheme == 'https' else 0
        features['has_ip'] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed.netloc) else 0
        features['has_at'] = 1 if '@' in url else 0
        
        # Suspicious keywords
        suspicious_keywords = ['login', 'verify', 'account', 'update', 'secure', 
                               'banking', 'confirm', 'suspend', 'restore', 'click']
        features['suspicious_keywords'] = sum(1 for kw in suspicious_keywords if kw in url.lower())
        
        # Domain analysis
        features['subdomain_count'] = len(ext.subdomain.split('.')) if ext.subdomain else 0
        features['tld_length'] = len(ext.suffix)
        
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']
        features['suspicious_tld'] = 1 if any(tld in url.lower() for tld in suspicious_tlds) else 0
        
        # Entropy
        def calculate_entropy(s):
            prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
            entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
            return entropy
        
        features['url_entropy'] = calculate_entropy(url) if len(url) > 0 else 0
        
        # Digit ratio
        digits = sum(c.isdigit() for c in url)
        letters = sum(c.isalpha() for c in url)
        features['digit_ratio'] = digits / letters if letters > 0 else 0
        
    except Exception as e:
        features = {key: 0 for key in [
            'url_length', 'domain_length', 'path_length', 'dots_count',
            'hyphen_count', 'underline_count', 'slash_count', 'question_count',
            'has_https', 'has_ip', 'has_at', 'suspicious_keywords',
            'subdomain_count', 'tld_length', 'suspicious_tld', 'url_entropy',
            'digit_ratio'
        ]}
    
    return features