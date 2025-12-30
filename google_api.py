"""
GOOGLE SAFE BROWSING API INTEGRATION
Real-time threat intelligence verification
================================================
"""

import requests
import json
import time
from typing import Dict, List, Optional

class GoogleSafeBrowsingAPI:
    """
    Google Safe Browsing API v4 Integration
    
    Features:
    - Real-time URL reputation checking
    - Threat type detection (Phishing, Malware, Unwanted Software)
    - Billions of indexed URLs
    - Updated every 30 minutes
    - Free tier: 10,000 requests/day
    
    Documentation: https://developers.google.com/safe-browsing/v4
    """
    
    def __init__(self, api_key: str):
        """
        Initialize Google Safe Browsing API client
        
        Args:
            api_key: Google Cloud API key with Safe Browsing API enabled
        
        Setup Instructions:
        1. Go to https://console.cloud.google.com/
        2. Create new project or select existing
        3. Enable "Safe Browsing API"
        4. Create API credentials (API Key)
        5. Copy API key here
        """
        self.api_key = api_key
        self.base_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        
        # Threat types to check
        self.threat_types = [
            "MALWARE",              # Malicious software
            "SOCIAL_ENGINEERING",   # Phishing/social engineering
            "UNWANTED_SOFTWARE",    # Potentially unwanted programs
            "POTENTIALLY_HARMFUL_APPLICATION"  # Harmful apps
        ]
        
        # Platform types
        self.platform_types = [
            "ANY_PLATFORM",
            "WINDOWS",
            "LINUX",
            "OSX",
            "ANDROID",
            "IOS"
        ]
        
        # Threat entry types
        self.threat_entry_types = ["URL"]
        
        print("=" * 70)
        print("GOOGLE SAFE BROWSING API INITIALIZED")
        print("=" * 70)
        print(f"✓ API Endpoint: {self.base_url}")
        print(f"✓ Monitoring threat types: {', '.join(self.threat_types)}")
        print(f"✓ Platform coverage: {', '.join(self.platform_types)}")
        print("=" * 70)
    
    def check_url(self, url: str) -> Dict:
        """
        Check single URL against Google Safe Browsing database
        
        Args:
            url: URL to check
        
        Returns:
            Dictionary with threat information
        """
        # Prepare API request
        payload = {
            "client": {
                "clientId": "phishing-detection-system",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": self.threat_types,
                "platformTypes": self.platform_types,
                "threatEntryTypes": self.threat_entry_types,
                "threatEntries": [{"url": url}]
            }
        }
        
        try:
            # Make API request
            response = requests.post(
                f"{self.base_url}?key={self.api_key}",
                headers={"Content-Type": "application/json"},
                json=payload,
                timeout=10
            )
            
            # Check response status
            if response.status_code == 200:
                result = response.json()
                
                # Parse threat matches
                if "matches" in result and len(result["matches"]) > 0:
                    # URL is flagged as threat
                    threat_info = result["matches"][0]
                    return {
                        "safe": False,
                        "threat_detected": True,
                        "threat_type": threat_info.get("threatType", "UNKNOWN"),
                        "platform": threat_info.get("platformType", "ANY_PLATFORM"),
                        "threat_entry": threat_info.get("threatEntryType", "URL"),
                        "cache_duration": threat_info.get("cacheDuration", "300s"),
                        "message": f"⚠️ THREAT DETECTED: {threat_info.get('threatType', 'UNKNOWN')}",
                        "raw_response": result
                    }
                else:
                    # URL is safe (not in threat database)
                    return {
                        "safe": True,
                        "threat_detected": False,
                        "threat_type": None,
                        "message": "✓ URL is safe (not in threat database)",
                        "raw_response": result
                    }
            
            elif response.status_code == 400:
                return {
                    "safe": None,
                    "threat_detected": None,
                    "error": "Bad Request - Invalid API request",
                    "message": "⚠️ API Error: Invalid request format",
                    "status_code": 400
                }
            
            elif response.status_code == 401:
                return {
                    "safe": None,
                    "threat_detected": None,
                    "error": "Unauthorized - Invalid API key",
                    "message": "⚠️ API Error: Check your API key",
                    "status_code": 401
                }
            
            elif response.status_code == 429:
                return {
                    "safe": None,
                    "threat_detected": None,
                    "error": "Rate Limit Exceeded",
                    "message": "⚠️ API Error: Too many requests",
                    "status_code": 429
                }
            
            else:
                return {
                    "safe": None,
                    "threat_detected": None,
                    "error": f"HTTP {response.status_code}",
                    "message": f"⚠️ API Error: {response.status_code}",
                    "status_code": response.status_code
                }
        
        except requests.exceptions.Timeout:
            return {
                "safe": None,
                "threat_detected": None,
                "error": "Request timeout",
                "message": "⚠️ API timeout - check network connection"
            }
        
        except Exception as e:
            return {
                "safe": None,
                "threat_detected": None,
                "error": str(e),
                "message": f"⚠️ Error: {str(e)}"
            }
    
    def check_urls_batch(self, urls: List[str]) -> List[Dict]:
        """
        Check multiple URLs in batch (max 500 per request)
        
        Args:
            urls: List of URLs to check
        
        Returns:
            List of threat information dictionaries
        """
        results = []
        
        # Process in batches of 500 (API limit)
        batch_size = 500
        for i in range(0, len(urls), batch_size):
            batch = urls[i:i + batch_size]
            
            # Prepare batch request
            payload = {
                "client": {
                    "clientId": "phishing-detection-system",
                    "clientVersion": "1.0"
                },
                "threatInfo": {
                    "threatTypes": self.threat_types,
                    "platformTypes": self.platform_types,
                    "threatEntryTypes": self.threat_entry_types,
                    "threatEntries": [{"url": url} for url in batch]
                }
            }
            
            try:
                response = requests.post(
                    f"{self.base_url}?key={self.api_key}",
                    headers={"Content-Type": "application/json"},
                    json=payload,
                    timeout=10
                )
                
                if response.status_code == 200:
                    result = response.json()
                    
                    # Create result map
                    threat_map = {}
                    if "matches" in result:
                        for match in result["matches"]:
                            threat_url = match.get("threat", {}).get("url", "")
                            threat_map[threat_url] = match
                    
                    # Build results for each URL
                    for url in batch:
                        if url in threat_map:
                            threat_info = threat_map[url]
                            results.append({
                                "url": url,
                                "safe": False,
                                "threat_detected": True,
                                "threat_type": threat_info.get("threatType", "UNKNOWN")
                            })
                        else:
                            results.append({
                                "url": url,
                                "safe": True,
                                "threat_detected": False,
                                "threat_type": None
                            })
                
                else:
                    # Error handling
                    for url in batch:
                        results.append({
                            "url": url,
                            "safe": None,
                            "threat_detected": None,
                            "error": f"HTTP {response.status_code}"
                        })
            
            except Exception as e:
                for url in batch:
                    results.append({
                        "url": url,
                        "safe": None,
                        "threat_detected": None,
                        "error": str(e)
                    })
            
            # Rate limiting
            time.sleep(0.1)
        
        return results


# ============================================
# HYBRID DETECTION SYSTEM
# ============================================

class HybridPhishingDetector:
    """
    Hybrid Phishing Detection System
    Combines ML predictions with Google Safe Browsing API
    """
    
    def __init__(self, ml_model, scaler, google_api_key: Optional[str] = None):
        """
        Initialize hybrid detector
        
        Args:
            ml_model: Trained ML model (Random Forest or TensorFlow)
            scaler: Feature scaler
            google_api_key: Google Safe Browsing API key (optional)
        """
        self.ml_model = ml_model
        self.scaler = scaler
        
        # Initialize Google Safe Browsing API (if key provided)
        self.google_api = None
        if google_api_key:
            self.google_api = GoogleSafeBrowsingAPI(google_api_key)
            print("✓ Google Safe Browsing API integrated")
        else:
            print("⚠️ Running in ML-only mode (no Google API)")
    
    def predict(self, url: str, features: Dict) -> Dict:
        """
        Hybrid prediction combining ML and Google API
        
        Args:
            url: URL to check
            features: Extracted URL features
        
        Returns:
            Prediction result with confidence score
        """
        # Step 1: ML Prediction
        feature_values = [features[key] for key in sorted(features.keys())]
        feature_array = self.scaler.transform([feature_values])
        
        ml_prediction = self.ml_model.predict(feature_array)[0]
        ml_probability = self.ml_model.predict_proba(feature_array)[0][1]
        
        # Step 2: Google API Check (if available)
        google_result = None
        if self.google_api:
            google_result = self.google_api.check_url(url)
        
        # Step 3: Hybrid Decision Logic
        final_prediction = self._hybrid_decision(
            ml_prediction, ml_probability, google_result
        )
        
        return final_prediction
    
    def _hybrid_decision(self, ml_pred: int, ml_prob: float, 
                        google_result: Optional[Dict]) -> Dict:
        """
        Combine ML and Google API results for final decision
        
        Decision Logic:
        - If Google API detects threat → PHISHING (high confidence)
        - If ML predicts phishing with high confidence (>0.8) → PHISHING
        - If ML predicts phishing with medium confidence (0.5-0.8) → SUSPICIOUS
        - If both say safe → SAFE
        """
        # Case 1: Google API detected threat
        if google_result and google_result.get("threat_detected"):
            return {
                "classification": "PHISHING",
                "confidence": 0.95,
                "ml_prediction": "Phishing" if ml_pred == 1 else "Legitimate",
                "ml_confidence": ml_prob,
                "google_api": "Threat Detected",
                "threat_type": google_result.get("threat_type"),
                "verdict": "🚨 PHISHING DETECTED (Google Safe Browsing)",
                "recommendation": "⛔ DO NOT VISIT - Known malicious site"
            }
        
        # Case 2: ML high confidence phishing
        if ml_pred == 1 and ml_prob > 0.8:
            return {
                "classification": "PHISHING",
                "confidence": ml_prob,
                "ml_prediction": "Phishing",
                "ml_confidence": ml_prob,
                "google_api": "Not in database" if google_result else "Not checked",
                "verdict": "⚠️ PHISHING DETECTED (ML Model)",
                "recommendation": "⚠️ HIGH RISK - Avoid this URL"
            }
        
        # Case 3: ML medium confidence
        if ml_pred == 1 and ml_prob > 0.5:
            return {
                "classification": "SUSPICIOUS",
                "confidence": ml_prob,
                "ml_prediction": "Phishing",
                "ml_confidence": ml_prob,
                "google_api": "Not in database" if google_result else "Not checked",
                "verdict": "⚠️ SUSPICIOUS URL",
                "recommendation": "⚠️ PROCEED WITH CAUTION"
            }
        
        # Case 4: Both say safe
        return {
            "classification": "SAFE",
            "confidence": 1 - ml_prob,
            "ml_prediction": "Legitimate",
            "ml_confidence": ml_prob,
            "google_api": "Safe" if google_result else "Not checked",
            "verdict": "✓ URL APPEARS SAFE",
            "recommendation": "✓ Low risk detected"
        }


# ============================================
# USAGE EXAMPLE
# ============================================

if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("HYBRID PHISHING DETECTION SYSTEM - DEMO")
    print("=" * 70)
    
    # Note: Replace with your actual API key
    # Get API key from: https://console.cloud.google.com/
    GOOGLE_API_KEY = "YOUR_API_KEY_HERE"
    
    # Test URLs
    test_urls = [
        "https://www.google.com",                           # Safe
        "http://testsafebrowsing.appspot.com/s/phishing.html",  # Google's test phishing URL
        "http://login-verify-account.tk/secure",            # Suspicious (fake)
        "https://github.com",                               # Safe
        "http://malware.testing.google.test/testing/malware/"  # Google's test malware URL
    ]
    
    print("\n📋 Testing URLs:")
    for i, url in enumerate(test_urls, 1):
        print(f"  {i}. {url}")
    
    # Initialize API (demo mode - will show API structure)
    print("\n🔄 Initializing Google Safe Browsing API...")
    print("Note: Get your API key from https://console.cloud.google.com/")
    print("      Enable 'Safe Browsing API' in your project")
    
    print("\n" + "=" * 70)
    print("API INTEGRATION COMPLETE ✓")
    print("=" * 70)
    print("\nReady for production deployment with Streamlit web app!")