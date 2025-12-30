import re
from urllib.parse import urlparse
import pickle
import os
from email_validator import validate_email, EmailNotValidError
from url_validator import validate_url_safety

class PhishingDetectionEngine:
    """
    Main detection engine using pre-trained ML models and feature extraction.
    Analyzes emails, URLs, and SMS for phishing indicators.
    """
    
    def __init__(self):
        # Load pre-trained models (in production, use joblib/pickle)
        self.email_model = self._load_model('models/email_classifier.pkl')
        self.url_model = self._load_model('models/url_classifier.pkl')
        self.sms_model = self._load_model('models/sms_classifier.pkl')
        
        # Suspicious keywords and patterns
        self.phishing_keywords = [
            'verify account', 'confirm identity', 'update payment',
            'unusual activity', 'click here immediately', 'act now',
            'validate credentials', 're-enter password', 'confirm banking'
        ]
        
        self.legitimate_domains = {
            'microsoft.com', 'google.com', 'amazon.com', 'apple.com',
            'github.com', 'stackoverflow.com'
        }
    
    def analyze(self, email_body='', sender='', url='', sms_text=''):
        """
        Main analysis function combining multiple detection methods.
        Returns classification and confidence score.
        """
        
        features = {}
        scores = []
        
        # Email analysis
        if email_body or sender:
            email_score, email_features = self._analyze_email(email_body, sender)
            scores.append(email_score)
            features.update(email_features)
        
        # URL analysis
        if url:
            url_score, url_features = self._analyze_url(url)
            scores.append(url_score)
            features.update(url_features)
        
        # SMS analysis
        if sms_text:
            sms_score, sms_features = self._analyze_sms(sms_text)
            scores.append(sms_score)
            features.update(sms_features)
        
        # Aggregate scores
        avg_score = sum(scores) / len(scores) if scores else 0.5
        
        # Classify
        classification = self._classify(avg_score)
        explanation = self._generate_explanation(features, classification)
        
        return {
            'classification': classification,
            'confidence': round(avg_score, 3),
            'features': features,
            'explanation': explanation,
            'risk_level': 'high' if avg_score > 0.7 else 'medium' if avg_score > 0.4 else 'low'
        }
    
    def _analyze_email(self, email_body, sender):
        """Analyze email for phishing indicators"""
        features = {}
        score = 0
        
        # Sender analysis
        sender_score = self._analyze_sender(sender)
        score += sender_score * 0.3
        features['sender_reputation'] = sender_score
        
        # Content analysis
        content_score = self._analyze_content(email_body)
        score += content_score * 0.4
        features['suspicious_content'] = content_score
        
        # URL in email analysis
        urls_in_email = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\$$\$$,]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', email_body)
        if urls_in_email:
            url_scores = [self._analyze_url(u)[0] for u in urls_in_email]
            url_score = max(url_scores) if url_scores else 0
            score += url_score * 0.3
            features['urls_found'] = len(urls_in_email)
            features['url_risk'] = url_score
        
        return min(score, 1.0), features
    
    def _analyze_url(self, url):
        """Analyze URL for phishing indicators"""
        features = {}
        score = 0
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Check domain reputation
            if domain in self.legitimate_domains:
                score += 0.1
                features['domain_reputation'] = 'trusted'
            else:
                # Check for suspicious patterns
                if self._is_suspicious_domain(domain):
                    score += 0.5
                    features['suspicious_domain'] = True
                
                # Check for homograph attacks (similar looking domains)
                if self._has_homograph_attack(domain):
                    score += 0.4
                    features['homograph_attack'] = True
            
            # Check URL structure
            if len(url) > 100:  # Unusually long URLs
                score += 0.2
                features['suspicious_length'] = True
            
            # Check for redirects
            if 'redirect' in url.lower() or 'go=' in url.lower():
                score += 0.3
                features['suspicious_redirect'] = True
            
            features['domain'] = domain
            
        except Exception as e:
            score = 0.5  # Uncertain
            features['parsing_error'] = str(e)
        
        return min(score, 1.0), features
    
    def _analyze_sms(self, sms_text):
        """Analyze SMS for smishing indicators"""
        features = {}
        score = 0
        
        # Urgent language
        urgent_keywords = ['urgent', 'immediately', 'act now', 'confirm now', 'verify']
        urgent_count = sum(1 for kw in urgent_keywords if kw in sms_text.lower())
        if urgent_count > 0:
            score += 0.3
            features['urgent_language'] = True
        
        # Suspicious URLs in SMS
        sms_urls = re.findall(r'http[s]?://\S+', sms_text)
        if sms_urls:
            score += 0.2
            features['sms_urls'] = len(sms_urls)
        
        # Shortened URLs (often used in phishing)
        shortened_patterns = ['bit.ly', 'tinyurl', 'short.link', 't.co']
        if any(pattern in sms_text for pattern in shortened_patterns):
            score += 0.3
            features['shortened_url'] = True
        
        # Missing sender information
        if len(sms_text) < 20:
            score += 0.1
            features['very_short_message'] = True
        
        features['text_length'] = len(sms_text)
        
        return min(score, 1.0), features
    
    def _analyze_sender(self, sender):
        """Analyze sender reputation"""
        score = 0
        
        try:
            validate_email(sender)
            domain = sender.split('@')[1]
            
            # Check if domain matches common enterprise domains
            if domain in ['gmail.com', 'outlook.com', 'yahoo.com']:
                score += 0.3  # Personal email
            else:
                score += 0.1  # Likely business email
                
        except EmailNotValidError:
            score = 0.7  # Invalid email format
        
        return score
    
    def _analyze_content(self, email_body):
        """Analyze email content for phishing indicators"""
        score = 0
        
        # Check for phishing keywords
        body_lower = email_body.lower()
        keyword_matches = sum(1 for kw in self.phishing_keywords if kw in body_lower)
        if keyword_matches > 0:
            score += min(keyword_matches * 0.15, 0.6)
        
        # Check for generic greetings (Dear user, Dear customer)
        if re.search(r'dear (user|customer|friend|sir|madam)', body_lower):
            score += 0.2
        
        # Check for requests for sensitive info
        sensitive_keywords = ['password', 'credit card', 'ssn', 'banking details']
        if any(kw in body_lower for kw in sensitive_keywords):
            score += 0.3
        
        # Check for urgent language
        if re.search(r'(urgent|immediately|asap|act now)', body_lower):
            score += 0.2
        
        return min(score, 1.0)
    
    def _is_suspicious_domain(self, domain):
        """Check if domain has suspicious characteristics"""
        # Excessive subdomains
        if domain.count('.') > 2:
            return True
        
        # Numbers that mimic letters
        suspicious_patterns = ['l0gin', 'passw0rd', 'verif1ed', 'amaz0n']
        if any(pattern in domain.lower() for pattern in suspicious_patterns):
            return True
        
        return False
    
    def _has_homograph_attack(self, domain):
        """Detect homograph attacks (visually similar domains)"""
        # Check against known legitimate domains
        similar_domains = {
            'google.com': ['goog1e.com', 'googlе.com', 'googie.com'],
            'amazon.com': ['amaz0n.com', 'amazоn.com'],
            'microsoft.com': ['microsoft.co', 'microsоft.com'],
        }
        
        for legit, suspicious in similar_domains.items():
            if domain in suspicious:
                return True
        
        return False
    
    def _classify(self, score):
        """Classify threat level based on score"""
        if score < 0.3:
            return 'safe'
        elif score < 0.6:
            return 'suspicious'
        else:
            return 'malicious'
    
    def _generate_explanation(self, features, classification):
        """Generate human-readable explanation"""
        reasons = []
        
        if features.get('suspicious_content'):
            reasons.append('Suspicious content detected in email')
        if features.get('suspicious_domain'):
            reasons.append('Domain reputation is questionable')
        if features.get('homograph_attack'):
            reasons.append('Possible domain spoofing detected')
        if features.get('urgent_language'):
            reasons.append('Excessive urgent language detected')
        if features.get('shortened_url'):
            reasons.append('Shortened URLs detected')
        if features.get('sender_reputation'):
            reasons.append('Sender reputation is low')
        
        if not reasons:
            reasons = [f'Content matches {classification} threat pattern']
        
        return ' | '.join(reasons[:3])  # Top 3 reasons
    
    def _load_model(self, model_path):
        """Load pre-trained ML model (mock implementation)"""
        # In production: load actual ML model using joblib
        # For now, return dummy model for demonstration
        if os.path.exists(model_path):
            with open(model_path, 'rb') as f:
                return pickle.load(f)
        return None
