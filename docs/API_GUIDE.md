# API Integration Guide

## Google Safe Browsing API Setup

### Step 1: Get API Key

1. Visit [Google Cloud Console](https://console.cloud.google.com/)
2. Create new project or select existing one
3. Enable "Safe Browsing API"
4. Navigate to Credentials → Create Credentials → API Key
5. Copy the generated API key

### Step 2: Configure Environment
```bash
# Create .env file
cp .env.example .env

# Edit and add your API key
GOOGLE_API_KEY=AIzaSyXXXXXXXXXXXXXXXXXXXXXXXX
```

### Step 3: Test API
```python
from google_api import GoogleSafeBrowsingAPI

api = GoogleSafeBrowsingAPI('your_api_key_here')
result = api.check_url('http://malware.testing.google.test/testing/malware/')
print(result)
```

### API Limits

- **Free Tier**: 10,000 requests per day
- **Rate Limit**: 100 requests per second
- **Update Frequency**: Every 30 minutes

### Test URLs (Provided by Google)

- **Malware Test**: `http://malware.testing.google.test/testing/malware/`
- **Phishing Test**: `http://testsafebrowsing.appspot.com/s/phishing.html`

### Error Handling
```python
result = api.check_url(url)

if result.get('safe') is None:
    print(f"API Error: {result.get('error')}")
elif result['threat_detected']:
    print(f"⚠️ Threat: {result['threat_type']}")
else:
    print("✓ URL is safe")
```

## Integration in App

The Streamlit app automatically uses the API if `GOOGLE_API_KEY` is set in environment variables.
```python
# In app.py
import os
from google_api import GoogleSafeBrowsingAPI

api_key = os.getenv('GOOGLE_API_KEY')
if api_key:
    google_api = GoogleSafeBrowsingAPI(api_key)
    result = google_api.check_url(user_url)
```
