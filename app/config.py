import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-very-secret-key-for-dev'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///security_platform.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)  # Session lasts 7 days
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')  # For VirusTotal API integration
    ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY') # For AbuseIPDB API integration
    GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY') # For Google Gemini API integration