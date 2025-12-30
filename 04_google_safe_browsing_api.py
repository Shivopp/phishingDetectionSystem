"""
Google Safe Browsing API Integration
Hybrid approach: ML prediction + Google's trusted API for additional security layer

Google Safe Browsing API:
- Checks URLs against Google's database of unsafe websites
- Real-time threat intelligence from billions of URLs
- Detects malware, phishing, unwanted software
- Free for legitimate use with API key
- Used by Chrome, Firefox, Safari browsers
"""

import requests
import json
import hashlib
import time
from typing import Dict, Tuple, List
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class GoogleSafeBrowsingAPI:
    """
    Integrates Google Safe Browsing API for URL threat checking
    
    Benefits:
    - Real-world threat data from Google's billions of indexed URLs
    - Up-to-date malware and phishing databases
    - Complements ML model predictions
    - Production-grade security verification
    """
    
    def __init__(self, api_key: str = None):
        """
        Initialize Google Safe Browsing API client
        
        Args:
            api_key: Google API key (get from https://developers.google.com/safe-browsing)
                     For demo, uses mock responses
        """
        self.api_key = api_key
        self.base_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        self.client_version = "1.0.0"
        self.timeout = 5
    
    def check_url(self, url: str) -> Dict:
        """
        Check URL using Google Safe Browsing API
        
        Args:
            url: URL to check
            
        Returns:
            Dict with threat information:
            {
                'safe': bool,
                'threat_type': str,
                'platform': str,
                'confidence': float,
                'api_response': dict
            }
        """
        if not self.api_key:
            logger.warning("No Google API key provided. Using mock response for demo.")
            return self._mock_api_response(url)
        
        try:
            # Build request payload
            payload = {
                "client": {
                    "clientId": "phishing-detection-system",
                    "clientVersion": self.client_version
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            # Make API request
            response = requests.post(
                f"{self.base_url}?key={self.api_key}",
                json=payload,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_api_response(data)
            else:
                logger.error(f"API error: {response.status_code} - {response.text}")
                return {
                    'safe': False,
                    'threat_type': 'API_ERROR',
                    'confidence': 0.0,
                    'api_response': {'error': response.text}
                }
        
        except requests.exceptions.Timeout:
            logger.error(f"API timeout for URL: {url}")
            return {
                'safe': False,
                'threat_type': 'API_TIMEOUT',
                'confidence': 0.0,
                'api_response': {'error': 'API timeout'}
            }
        except Exception as e:
            logger.error(f"API error: {str(e)}")
            return {
                'safe': False,
                'threat_type': 'API_ERROR',
                'confidence': 0.0,
                'api_response': {'error': str(e)}
            }
    
    def _parse_api_response(self, response: Dict) -> Dict:
        """Parse Google Safe Browsing API response"""
        if 'matches' not in response or not response['matches']:
            return {
                'safe': True,
                'threat_type': 'NONE',
                'platform': 'ANY_PLATFORM',
                'confidence': 1.0,
                'api_response': response
            }
        
        match = response['matches'][0]
        threat_confidence = self._threat_to_confidence(match.get('threatType', 'UNKNOWN'))
        
        return {
            'safe': False,
            'threat_type': match.get('threatType', 'UNKNOWN'),
            'platform': match.get('platformType', 'UNKNOWN'),
            'confidence': threat_confidence,
            'api_response': response
        }
    
    def _threat_to_confidence(self, threat_type: str) -> float:
        """Convert threat type to confidence score"""
        threat_scores = {
            'MALWARE': 0.95,
            'SOCIAL_ENGINEERING': 0.90,  # Phishing falls here
            'UNWANTED_SOFTWARE': 0.85,
            'POTENTIALLY_HARMFUL_APPLICATION': 0.80,
        }
        return threat_scores.get(threat_type, 0.75)
    
    def _mock_api_response(self, url: str) -> Dict:
        """
        Generate mock API response for demo purposes
        In production, use real Google API key
        """
        phishing_indicators = [
            'verify', 'confirm', 'update', 'login', 'secure',
            'account', 'paypal', 'amazon', 'bank', 'google',
            'facebook', 'password', 'credential', 'alert'
        ]
        
        url_lower = url.lower()
        is_phishing = any(indicator in url_lower for indicator in phishing_indicators)
        
        if is_phishing:
            return {
                'safe': False,
                'threat_type': 'SOCIAL_ENGINEERING',
                'platform': 'ANY_PLATFORM',
                'confidence': 0.85,
                'api_response': {
                    'matches': [{
                        'threatType': 'SOCIAL_ENGINEERING',
                        'platformType': 'ANY_PLATFORM'
                    }]
                }
            }
        else:
            return {
                'safe': True,
                'threat_type': 'NONE',
                'platform': 'ANY_PLATFORM',
                'confidence': 1.0,
                'api_response': {}
            }


class HybridPhishingDetector:
    """
    Hybrid detection system combining:
    - ML model predictions (Random Forest / TensorFlow)
    - Google Safe Browsing API verification
    """
    
    def __init__(self, ml_model, google_api_client: GoogleSafeBrowsingAPI):
        """
        Initialize hybrid detector
        
        Args:
            ml_model: Trained ML model (must have predict_proba method)
            google_api_client: GoogleSafeBrowsingAPI instance
        """
        self.ml_model = ml_model
        self.google_api = google_api_client
    
    def detect_phishing(self, url: str, features_df) -> Dict:
        """
        Detect phishing using hybrid approach
        
        Returns:
            {
                'url': str,
                'ml_prediction': {
                    'class': 'PHISHING' | 'LEGITIMATE',
                    'confidence': float,
                    'probability': float
                },
                'api_verification': {
                    'safe': bool,
                    'threat_type': str,
                    'confidence': float
                },
                'final_verdict': {
                    'class': 'PHISHING' | 'SUSPICIOUS' | 'LEGITIMATE',
                    'confidence': float,
                    'explanation': str,
                    'risk_score': float
                }
            }
        """
        # ML Model Prediction
        ml_result = self._ml_predict(url, features_df)
        
        # Google Safe Browsing API Check
        api_result = self.google_api.check_url(url)
        
        # Combine results for final verdict
        final_verdict = self._combine_results(ml_result, api_result, url)
        
        return {
            'url': url,
            'ml_prediction': ml_result,
            'api_verification': api_result,
            'final_verdict': final_verdict,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def _ml_predict(self, url: str, features_df) -> Dict:
        """Get ML model prediction"""
        # Extract features for this URL (simplified - in production, use full feature extraction)
        try:
            # This assumes features_df has the features extracted
            ml_prob = self.ml_model.predict_proba([features_df])[0]
            phishing_prob = ml_prob[1]
            
            return {
                'class': 'PHISHING' if phishing_prob > 0.5 else 'LEGITIMATE',
                'confidence': max(ml_prob),
                'probability': phishing_prob
            }
        except Exception as e:
            logger.error(f"ML prediction error: {str(e)}")
            return {
                'class': 'UNKNOWN',
                'confidence': 0.0,
                'probability': 0.0
            }
    
    def _combine_results(self, ml_result: Dict, api_result: Dict, url: str) -> Dict:
        """
        Combine ML and API results with intelligent weighting
        
        Weighting Strategy:
        - ML Model: 60% weight (trained on real dataset)
        - Google API: 40% weight (real-world threat data)
        """
        ml_conf = ml_result['confidence']
        api_conf = api_result['confidence']
        
        # Weighted confidence score
        combined_confidence = (ml_conf * 0.6) + (api_conf * 0.4)
        
        # Determine final class
        if api_result['safe']:  # If Google API says safe, likely safe
            final_class = 'LEGITIMATE'
            risk_score = (ml_result['probability'] * 0.6) + (1 - api_result['confidence']) * 0.4
        elif ml_result['class'] == 'PHISHING' and api_result['safe'] == False:
            final_class = 'PHISHING'
            risk_score = min(combined_confidence, 1.0)
        elif ml_result['probability'] > 0.6 and api_result['confidence'] > 0.5:
            final_class = 'PHISHING'
            risk_score = combined_confidence
        else:
            final_class = 'SUSPICIOUS'
            risk_score = combined_confidence
        
        # Generate explanation
        explanation = self._generate_explanation(ml_result, api_result, final_class, url)
        
        return {
            'class': final_class,
            'confidence': combined_confidence,
            'explanation': explanation,
            'risk_score': min(risk_score, 1.0)
        }
    
    def _generate_explanation(self, ml_result: Dict, api_result: Dict, final_class: str, url: str) -> str:
        """Generate human-readable explanation"""
        explanations = []
        
        # ML analysis
        if ml_result['class'] == 'PHISHING':
            explanations.append(f"ML model detected phishing patterns (confidence: {ml_result['confidence']:.2%})")
        else:
            explanations.append(f"ML model indicates legitimate URL (confidence: {ml_result['confidence']:.2%})")
        
        # API analysis
        if not api_result['safe']:
            explanations.append(f"Google Safe Browsing flagged as {api_result['threat_type']}")
        else:
            explanations.append("Google Safe Browsing database shows no known threats")
        
        # Final verdict
        if final_class == 'PHISHING':
            explanations.append("VERDICT: High risk - Do not interact with this URL")
        elif final_class == 'SUSPICIOUS':
            explanations.append("VERDICT: Moderate risk - Exercise caution before clicking")
        else:
            explanations.append("VERDICT: Safe to visit")
        
        return "; ".join(explanations)


# Demo usage
if __name__ == "__main__":
    print("Google Safe Browsing API Integration Demo")
    print("=" * 60)
    
    # Initialize Google Safe Browsing API
    google_api = GoogleSafeBrowsingAPI(api_key=None)  # None uses mock responses
    
    # Test URLs
    test_urls = [
        'https://www.google.com',
        'https://www.g00gle-verify-account.tk/login',
        'https://www.facebook.com/login',
        'https://secure-bank-update.ru/signin',
    ]
    
    print("\nTesting Google Safe Browsing API:\n")
    for url in test_urls:
        result = google_api.check_url(url)
        print(f"URL: {url}")
        print(f"Safe: {result['safe']}")
        print(f"Threat Type: {result['threat_type']}")
        print(f"Confidence: {result['confidence']:.2%}\n")
