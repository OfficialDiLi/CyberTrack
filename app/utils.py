import requests
import os
from datetime import datetime, timedelta
import google.generativeai as genai
from app.config import Config
import random
import whois # Import the whois library

def analyze_url_virustotal(url):
    """
    Analyze URL using VirusTotal API
    Returns a dictionary with verdict, confidence, and summary.
    """
    api_key = Config.VIRUSTOTAL_API_KEY
    if not api_key:
        return {
            'source': 'VirusTotal',
            'verdict': 'UNKNOWN',
            'confidence': 0.0,
            'summary': 'VirusTotal API key not configured.'
        }
    
    try:
        url_id = requests.utils.quote(url, safe='')
        headers = {'x-apikey': api_key}
        
        analysis_url = f'https://www.virustotal.com/api/v3/urls'
        response = requests.post(analysis_url, data={'url': url}, headers=headers)
        
        if response.status_code == 200:
            url_id = response.json()['data']['id']
            report_url = f'https://www.virustotal.com/api/v3/analyses/{url_id}'
            report_response = requests.get(report_url, headers=headers)
            
            if report_response.status_code == 200:
                stats = report_response.json()['data']['attributes']['stats']
                total_engines = sum(stats.values())
                malicious_count = stats.get('malicious', 0)
                
                if total_engines > 0:
                    confidence = (malicious_count / total_engines) * 100
                    if malicious_count > 0:
                        verdict = 'MALICIOUS'
                        summary = f'{malicious_count}/{total_engines} engines flagged this URL as malicious.'
                    else:
                        verdict = 'BENIGN'
                        summary = 'No engines flagged this URL as malicious.'
                else:
                    verdict = 'UNKNOWN'
                    confidence = 0.0
                    summary = 'No analysis data available from VirusTotal.'
                
                return {'source': 'VirusTotal', 'verdict': verdict, 'confidence': confidence, 'summary': summary}
        
        return {'source': 'VirusTotal', 'verdict': 'ERROR', 'confidence': 0.0, 'summary': 'Failed to get analysis from VirusTotal.'}
            
    except Exception as e:
        return {'source': 'VirusTotal', 'verdict': 'ERROR', 'confidence': 0.0, 'summary': f'VirusTotal API error: {e}'}


def analyze_ip_abuseipdb(ip):
    """
    Analyze IP using AbuseIPDB API
    Returns a dictionary with all relevant fields from the API response.
    """
    api_key = Config.ABUSEIPDB_API_KEY
    if not api_key:
        return {'source': 'AbuseIPDB', 'verdict': 'UNKNOWN', 'confidence': 0.0, 'summary': 'AbuseIPDB API key not configured.', 'details': {}}
    
    try:
        headers = {'Key': api_key, 'Accept': 'application/json'}
        params = {'ipAddress': ip, 'maxAgeInDays': '90', 'verbose': ''}
        response = requests.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params)
        
        if response.status_code == 200:
            data = response.json()['data']
            confidence = data.get('abuseConfidenceScore', 0)
            
            if confidence > 75:
                verdict = 'MALICIOUS'
            elif confidence > 25:
                verdict = 'SUSPICIOUS'
            else:
                verdict = 'BENIGN'
            
            return {
                'source': 'AbuseIPDB',
                'verdict': verdict,
                'confidence': confidence,
                'summary': f"Abuse confidence score: {confidence}",
                'details': data
            }
        
        return {'source': 'AbuseIPDB', 'verdict': 'ERROR', 'confidence': 0.0, 'summary': 'Failed to get analysis from AbuseIPDB.', 'details': {}}
            
    except Exception as e:
        return {'source': 'AbuseIPDB', 'verdict': 'ERROR', 'confidence': 0.0, 'summary': f'AbuseIPDB API error: {e}', 'details': {}}


def analyze_domain_virustotal(domain):
    """
    Analyze domain using VirusTotal API
    Returns a dictionary with verdict, confidence, and summary.
    """
    api_key = Config.VIRUSTOTAL_API_KEY
    if not api_key:
        return {'source': 'VirusTotal', 'verdict': 'UNKNOWN', 'confidence': 0.0, 'summary': 'VirusTotal API key not configured.'}
    
    try:
        headers = {'x-apikey': api_key}
        report_url = f'https://www.virustotal.com/api/v3/domains/{domain}'
        response = requests.get(report_url, headers=headers)
        
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            total_engines = sum(stats.values())
            malicious_count = stats.get('malicious', 0)
            
            if total_engines > 0:
                confidence = (malicious_count / total_engines) * 100
                if malicious_count > 0:
                    verdict = 'MALICIOUS'
                    summary = f'{malicious_count}/{total_engines} engines flagged this domain as malicious.'
                else:
                    verdict = 'BENIGN'
                    summary = 'No engines flagged this domain as malicious.'
            else:
                verdict = 'UNKNOWN'
                confidence = 0.0
                summary = 'No analysis data available from VirusTotal.'
                
            return {'source': 'VirusTotal', 'verdict': verdict, 'confidence': confidence, 'summary': summary}
        
        return {'source': 'VirusTotal', 'verdict': 'ERROR', 'confidence': 0.0, 'summary': 'Failed to get analysis from VirusTotal.'}
            
    except Exception as e:
        return {'source': 'VirusTotal', 'verdict': 'ERROR', 'confidence': 0.0, 'summary': f'VirusTotal API error: {e}'}

def analyze_domain_whois(domain_name):
    """
    Retrieves WHOIS information for a given domain name.
    Returns a dictionary with WHOIS details.
    """
    try:
        domain_info = whois.whois(domain_name)
        
        if domain_info and domain_info.domain_name:
            details = {
                'domain_name': domain_info.domain_name,
                'registrar': domain_info.registrar,
                'creation_date': str(domain_info.creation_date),
                'expiration_date': str(domain_info.expiration_date),
                'updated_date': str(domain_info.updated_date),
                'name_servers': domain_info.name_servers,
                'emails': domain_info.emails,
                'organization': domain_info.org,
                'address': domain_info.address,
                'city': domain_info.city,
                'state': domain_info.state,
                'zipcode': domain_info.zipcode,
                'country': domain_info.country,
            }
            return {
                'source': 'WHOIS',
                'verdict': 'BENIGN', # WHOIS itself doesn't give a threat verdict
                'confidence': 0.0,
                'summary': 'WHOIS information retrieved successfully.',
                'details': details
            }
        else:
            return {
                'source': 'WHOIS',
                'verdict': 'UNKNOWN',
                'confidence': 0.0,
                'summary': 'WHOIS data empty or incomplete.',
                'details': {}
            }
    except Exception as e:
        return {
            'source': 'WHOIS',
            'verdict': 'ERROR',
            'confidence': 0.0,
            'summary': f'Error retrieving WHOIS info: {e}',
            'details': {}
        }


def analyze_file_virustotal(file_hash):
    """
    Analyze file using VirusTotal API
    Returns a dictionary with verdict, confidence, and summary.
    """
    api_key = Config.VIRUSTOTAL_API_KEY
    if not api_key:
        return {'source': 'VirusTotal', 'verdict': 'UNKNOWN', 'confidence': 0.0, 'summary': 'VirusTotal API key not configured.'}
    
    try:
        headers = {'x-apikey': api_key}
        report_url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        response = requests.get(report_url, headers=headers)
        
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            total_engines = sum(stats.values())
            malicious_count = stats.get('malicious', 0)
            
            if total_engines > 0:
                confidence = (malicious_count / total_engines) * 100
                if malicious_count > 0:
                    verdict = 'MALICIOUS'
                    summary = f'{malicious_count}/{total_engines} engines flagged this file as malicious.'
                else:
                    verdict = 'BENIGN'
                    summary = 'No engines flagged this file as malicious.'
            else:
                verdict = 'UNKNOWN'
                confidence = 0.0
                summary = 'No analysis data available from VirusTotal.'
                
            return {'source': 'VirusTotal', 'verdict': verdict, 'confidence': confidence, 'summary': summary}
        
        return {'source': 'VirusTotal', 'verdict': 'ERROR', 'confidence': 0.0, 'summary': 'Failed to get analysis from VirusTotal.'}
            
    except Exception as e:
        return {'source': 'VirusTotal', 'verdict': 'ERROR', 'confidence': 0.0, 'summary': f'VirusTotal API error: {e}'}


def simulate_analysis(input_value, scan_type):
    """
    Simulate threat analysis for fallback.
    """
    lower_value = input_value.lower()
    if 'phish' in lower_value or 'malware' in lower_value or 'bosu.edu.ng' in lower_value:
        verdict = 'MALICIOUS'
        confidence = random.uniform(80, 95)
        summary = 'Simulated analysis determined this is malicious.'
    elif 'bank' in lower_value or 'login' in lower_value or '192.168' in lower_value or 'admin' in lower_value:
        verdict = 'SUSPICIOUS'
        confidence = random.uniform(70, 85)
        summary = 'Simulated analysis suggests this is suspicious.'
    else:
        verdict = 'BENIGN'
        confidence = random.uniform(70, 95)
        summary = 'Simulated analysis determined this is benign.'

    return {'source': 'Simulation', 'verdict': verdict, 'confidence': confidence, 'summary': summary}

def fetch_abuseipdb_blacklist():
    """
    Fetches the AbuseIPDB blacklist.
    """
    api_key = Config.ABUSEIPDB_API_KEY
    if not api_key:
        return [
            {'type': 'Simulated Phishing', 'indicator': '1.1.1.1', 'severity': 'High', 'timestamp': datetime.now().isoformat()},
            {'type': 'Simulated Malware C2', 'indicator': '2.2.2.2', 'severity': 'Critical', 'timestamp': (datetime.now() - timedelta(minutes=30)).isoformat()},
        ]

    url = 'https://api.abuseipdb.com/api/v2/blacklist'
    headers = {'Key': api_key, 'Accept': 'application/json'}
    params = {'limit': 50, 'confidenceMinimum': 90}

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        
        return [{
            'type': 'AbuseIPDB Blacklist',
            'indicator': entry.get('ipAddress'),
            'severity': 'High' if entry.get('abuseConfidenceScore', 0) >= 90 else 'Medium',
            'confidence': entry.get('abuseConfidenceScore'),
            'country_code': entry.get('countryCode'),
            'last_reported': entry.get('lastReportedAt'),
            'timestamp': datetime.now().isoformat()
        } for entry in data.get('data', [])]
    except requests.exceptions.RequestException as e:
        print(f"Error fetching AbuseIPDB blacklist: {e}")
        return []

def analyze_url_local_model(url):
    """
    Analyzes a URL using a simple rule-based local model.
    This is a placeholder for a more advanced ML model.
    """
    verdict = 'BENIGN'
    confidence = random.uniform(70, 80)
    summary = "Local model: No immediate threats detected."
    lower_url = url.lower()

    if any(keyword in lower_url for keyword in ['login', 'verify', 'account', 'update', 'security', 'paypal', 'bank']):
        verdict = 'SUSPICIOUS'
        confidence = random.uniform(70, 85)
        summary = "Local model: URL contains suspicious keywords."

    domain_part = url.split('//')[-1].split('/')[0]
    if any(char.isdigit() for char in domain_part) and '.' in domain_part:
        parts = domain_part.split('.')
        if all(part.isdigit() for part in parts) and len(parts) == 4:
            verdict = 'MALICIOUS'
            confidence = random.uniform(85, 95)
            summary = "Local model: URL uses an IP address instead of a domain name."

    if any(lower_url.endswith(tld) for tld in ['.zip', '.xyz', '.top', '.club', '.online', '.site']):
        verdict = 'SUSPICIOUS'
        confidence = max(confidence, random.uniform(70, 80))
        summary = "Local model: URL uses a suspicious TLD."

    if len(url) > 100:
        verdict = 'SUSPICIOUS'
        confidence = max(confidence, random.uniform(70, 80))
        summary = "Local model: URL is unusually long."
        
    if lower_url.count('.') > 5 or '%' in lower_url or '@' in lower_url:
        verdict = 'SUSPICIOUS'
        confidence = max(confidence, random.uniform(75, 85))
        summary = "Local model: URL contains multiple subdomains or unusual characters."

    return {'source': 'Local Model', 'verdict': verdict, 'confidence': confidence, 'summary': summary}

def analyze_url_gemini(url):
    """
    Analyzes a URL using the Google Gemini API.
    """
    api_key = Config.GEMINI_API_KEY
    if not api_key:
        return {'source': 'Gemini', 'verdict': 'UNKNOWN', 'confidence': 0.0, 'summary': 'Gemini API key not configured.'}

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-2.5-flash')

    prompt = f"""
    Analyze the following URL for potential threats. Provide a verdict (MALICIOUS, SUSPICIOUS, BENIGN), 
    a confidence score (0-100), and a brief summary.
    URL: {url}
    
    Example:
    VERDICT: MALICIOUS
    CONFIDENCE: 95
    SUMMARY: This URL is a phishing site.
    """

    try:
        response = model.generate_content(prompt)
        text_response = response.text.strip()

        verdict = 'UNKNOWN'
        confidence = 0.0
        summary = "Could not parse Gemini response."

        for line in text_response.split('\n'):
            if line.startswith('VERDICT:'):
                verdict = line.split(':', 1)[1].strip().upper()
            elif line.startswith('CONFIDENCE:'):
                confidence = float(line.split(':', 1)[1].strip())
            elif line.startswith('SUMMARY:'):
                summary = line.split(':', 1)[1].strip()
        
        if verdict not in ['MALICIOUS', 'SUSPICIOUS', 'BENIGN']:
            verdict = 'UNKNOWN'
            summary = f"Gemini: Unclear verdict. Raw response: {text_response}"

        return {'source': 'Gemini', 'verdict': verdict, 'confidence': confidence, 'summary': summary}

    except Exception as e:
        return {'source': 'Gemini', 'verdict': 'ERROR', 'confidence': 0.0, 'summary': f'Gemini API error: {e}'}
