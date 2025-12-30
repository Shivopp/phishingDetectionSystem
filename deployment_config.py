"""
Production deployment configuration for the phishing detection system.
Includes logging, error handling, and security settings.
"""

import logging
from datetime import datetime

class ProductionConfig:
    """Production environment configuration"""
    
    # Flask settings
    DEBUG = False
    TESTING = False
    
    # Security
    CORS_ORIGINS = ['https://yourdomain.com']
    RATE_LIMIT = 100  # requests per minute
    
    # Database (in production, use actual DB)
    DATABASE_URL = 'postgresql://user:password@localhost:5432/phishing_detection'
    
    # Logging
    LOG_LEVEL = 'INFO'
    LOG_FILE = '/var/log/phishing-detection/app.log'
    
    @staticmethod
    def setup_logging():
        """Setup application logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(ProductionConfig.LOG_FILE),
                logging.StreamHandler()
            ]
        )

class DevelopmentConfig:
    """Development environment configuration"""
    DEBUG = True
    TESTING = False
    CORS_ORIGINS = ['*']
    RATE_LIMIT = None

# Environment-based config selection
def get_config(environment='development'):
    """Get configuration based on environment"""
    if environment == 'production':
        return ProductionConfig
    return DevelopmentConfig
