import json
from datetime import datetime
from collections import defaultdict

class Database:
    """
    In-memory database for storing detection results.
    In production: use PostgreSQL, MongoDB, etc.
    """
    
    def __init__(self):
        self.detections = []
        self.responses = []
        self.whitelist = set()
        self.blacklist = set()
    
    def store_detection(self, detection_record):
        """Store detection result"""
        self.detections.append(detection_record)
    
    def store_response_log(self, response_record):
        """Store automated response"""
        self.responses.append(response_record)
    
    def get_detections(self, limit=100, classification=None):
        """Retrieve detection history"""
        results = self.detections[::-1]  # Latest first
        
        if classification:
            results = [d for d in results if d.get('classification') == classification]
        
        return results[:limit]
    
    def get_stats(self):
        """Get detection statistics"""
        total = len(self.detections)
        safe = len([d for d in self.detections if d.get('classification') == 'safe'])
        suspicious = len([d for d in self.detections if d.get('classification') == 'suspicious'])
        malicious = len([d for d in self.detections if d.get('classification') == 'malicious'])
        
        return {
            'total_detections': total,
            'safe': safe,
            'suspicious': suspicious,
            'malicious': malicious,
            'safe_percentage': round(safe / total * 100, 1) if total > 0 else 0,
            'malicious_percentage': round(malicious / total * 100, 1) if total > 0 else 0
        }
    
    def add_whitelist(self, sender, domain):
        """Add to whitelist"""
        if sender:
            self.whitelist.add(sender)
        if domain:
            self.whitelist.add(domain)
    
    def add_blacklist(self, sender, domain):
        """Add to blacklist"""
        if sender:
            self.blacklist.add(sender)
        if domain:
            self.blacklist.add(domain)
    
    def is_whitelisted(self, value):
        return value in self.whitelist
    
    def is_blacklisted(self, value):
        return value in self.blacklist
