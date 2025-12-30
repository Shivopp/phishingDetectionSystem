def validate_url_safety(url):
    """Validate URL safety (mock implementation)"""
    suspicious_tlds = ['.tk', '.ml', '.ga']
    
    for tld in suspicious_tlds:
        if url.endswith(tld):
            return False
    
    return True
