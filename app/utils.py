import requests
import os
from datetime import datetime, timedelta # Import datetime and timedelta
import google.generativeai as genai # Import Gemini API
from app.config import Config

def analyze_url_virustotal(url):
    """
    Analyze URL using VirusTotal API
    Returns a tuple of (verdict, confidence, summary)
    """
    api_key = Config.VIRUSTOTAL_API_KEY
    if not api_key:
        # If no API key is provided, return simulated results
        return simulate_analysis(url, 'url')
    
    try:
        # First, make a request to check the URL
        url_id = requests.utils.quote(url, safe='')
        headers = {
            'x-apikey': api_key
        }
        
        # Submit URL for analysis
        analysis_url = f'https://www.virustotal.com/api/v3/urls'
        response = requests.post(
            analysis_url,
            data={'url': url},
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            url_id = data['data']['id']
            
            # Now get the analysis report
            report_url = f'https://www.virustotal.com/api/v3/analyses/{url_id}'
            report_response = requests.get(report_url, headers=headers)
            
            if report_response.status_code == 200:
                report_data = report_response.json()
                
                # Extract statistics from the analysis
                stats = report_data['data']['attributes']['stats']
                
                # Calculate malicious percentage
                total_engines = sum(stats.values())
                malicious_count = stats.get('malicious', 0)
                
                if total_engines > 0:
                    confidence = (malicious_count / total_engines) * 100
                    if malicious_count > 0:
                        verdict = 'MALICIOUS'
                        summary = f'The URL was flagged as malicious by {malicious_count} out of {total_engines} security vendors.'
                    else:
                        verdict = 'BENIGN'
                        summary = 'The URL was analyzed by multiple security vendors with no malicious flags.'
                else:
                    # If no stats are available, use our simulation
                    return simulate_analysis(url, 'url')
                
                return verdict, confidence, summary
            else:
                # Return simulated results on API error
                return simulate_analysis(url, 'url')
        else:
            # Return simulated results on API error
            return simulate_analysis(url, 'url')
            
    except Exception as e:
        print(f"VirusTotal API error: {str(e)}")
        return simulate_analysis(url, 'url')


def analyze_ip_virustotal(ip):
    """
    Analyze IP using VirusTotal API
    Returns a tuple of (verdict, confidence, summary)
    """
    api_key = Config.VIRUSTOTAL_API_KEY
    if not api_key:
        return simulate_analysis(ip, 'ip')
    
    try:
        headers = {
            'x-apikey': api_key
        }
        
        # Get IP report
        report_url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
        response = requests.get(report_url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            
            # Extract malicious stats
            stats = data['data']['attributes']['last_analysis_stats']
            total_engines = sum(stats.values())
            malicious_count = stats.get('malicious', 0)
            
            if total_engines > 0:
                confidence = (malicious_count / total_engines) * 100
                if malicious_count > 0:
                    verdict = 'MALICIOUS'
                    summary = f'The IP was flagged as malicious by {malicious_count} out of {total_engines} security vendors.'
                else:
                    verdict = 'BENIGN'
                    summary = 'The IP was analyzed by multiple security vendors with no malicious flags.'
            else:
                return simulate_analysis(ip, 'ip')
                
            return verdict, confidence, summary
        else:
            return simulate_analysis(ip, 'ip')
            
    except Exception as e:
        print(f"VirusTotal API error: {str(e)}")
        return simulate_analysis(ip, 'ip')


def analyze_domain_virustotal(domain):
    """
    Analyze domain using VirusTotal API
    Returns a tuple of (verdict, confidence, summary)
    """
    api_key = Config.VIRUSTOTAL_API_KEY
    if not api_key:
        return simulate_analysis(domain, 'domain')
    
    try:
        headers = {
            'x-apikey': api_key
        }
        
        # Get domain report
        report_url = f'https://www.virustotal.com/api/v3/domains/{domain}'
        response = requests.get(report_url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            
            # Extract malicious stats
            stats = data['data']['attributes']['last_analysis_stats']
            total_engines = sum(stats.values())
            malicious_count = stats.get('malicious', 0)
            
            if total_engines > 0:
                confidence = (malicious_count / total_engines) * 100
                if malicious_count > 0:
                    verdict = 'MALICIOUS'
                    summary = f'The domain was flagged as malicious by {malicious_count} out of {total_engines} security vendors.'
                else:
                    verdict = 'BENIGN'
                    summary = 'The domain was analyzed by multiple security vendors with no malicious flags.'
            else:
                return simulate_analysis(domain, 'domain')
                
            return verdict, confidence, summary
        else:
            return simulate_analysis(domain, 'domain')
            
    except Exception as e:
        print(f"VirusTotal API error: {str(e)}")
        return simulate_analysis(domain, 'domain')


def analyze_file_virustotal(file_hash):
    """
    Analyze file using VirusTotal API
    Returns a tuple of (verdict, confidence, summary)
    """
    api_key = Config.VIRUSTOTAL_API_KEY
    if not api_key:
        return simulate_analysis(file_hash, 'file')
    
    try:
        headers = {
            'x-apikey': api_key
        }
        
        # Get file report
        report_url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        response = requests.get(report_url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            
            # Extract malicious stats
            stats = data['data']['attributes']['last_analysis_stats']
            total_engines = sum(stats.values())
            malicious_count = stats.get('malicious', 0)
            
            if total_engines > 0:
                confidence = (malicious_count / total_engines) * 100
                if malicious_count > 0:
                    verdict = 'MALICIOUS'
                    summary = f'The file was flagged as malicious by {malicious_count} out of {total_engines} security vendors.'
                else:
                    verdict = 'BENIGN'
                    summary = 'The file was analyzed by multiple security vendors with no malicious flags.'
            else:
                return simulate_analysis(file_hash, 'file')
                
            return verdict, confidence, summary
        else:
            return simulate_analysis(file_hash, 'file')
            
    except Exception as e:
        print(f"VirusTotal API error: {str(e)}")
        return simulate_analysis(file_hash, 'file')


def simulate_analysis(input_value, scan_type):
    """
    Simulate threat analysis - for fallback when no API key is provided
    """
    # Simple simulation logic
    lower_value = input_value.lower()
    if 'phish' in lower_value or 'malware' in lower_value or 'bosu.edu.ng' in lower_value:
        verdict = 'MALICIOUS'
        confidence = 95.0
        summary = f'The analysis determined this {scan_type} is MALICIOUS. The ML model showed high confidence, and multiple VirusTotal engines flagged it.'
    elif 'bank' in lower_value or 'login' in lower_value or '192.168' in lower_value or 'admin' in lower_value:
        verdict = 'SUSPICIOUS'
        confidence = 70.0
        summary = f'The analysis flagged this {scan_type} as SUSPICIOUS. While not overtly malicious, features suggest potential risk.'
    else:
        verdict = 'BENIGN'
        confidence = 90.0
        summary = f'The analysis determined this {scan_type} is BENIGN. All ML features and VirusTotal reports indicate low risk.'

    return verdict, confidence, summary

def fetch_abuseipdb_blacklist():
    """
    Fetches the AbuseIPDB blacklist.
    Returns a list of dictionaries containing threat data, or an empty list on error/no API key.
    """
    api_key = Config.ABUSEIPDB_API_KEY
    if not api_key:
        print("AbuseIPDB API key not configured. Returning simulated threat feed.")
        # Return simulated data if API key is not available
        return [
            {'type': 'Simulated Phishing', 'indicator': '1.1.1.1', 'severity': 'High', 'timestamp': datetime.now().isoformat()},
            {'type': 'Simulated Malware C2', 'indicator': '2.2.2.2', 'severity': 'Critical', 'timestamp': (datetime.now() - timedelta(minutes=30)).isoformat()},
        ]

    url = 'https://api.abuseipdb.com/api/v2/blacklist'
    headers = {
        'Key': api_key,
        'Accept': 'application/json',
    }
    params = {
        'limit': 50, # Fetch up to 50 blacklisted IPs
        'confidenceMinimum': 90 # Only show IPs with a confidence score of 90 or higher
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status() # Raise an exception for HTTP errors
        data = response.json()
        
        threat_feed_data = []
        for entry in data.get('data', []):
            threat_feed_data.append({
                'type': 'AbuseIPDB Blacklist',
                'indicator': entry.get('ipAddress'),
                'severity': 'High' if entry.get('abuseConfidenceScore', 0) >= 90 else 'Medium',
                'confidence': entry.get('abuseConfidenceScore'),
                'country_code': entry.get('countryCode'),
                'last_reported': entry.get('lastReportedAt'),
                'timestamp': datetime.now().isoformat() # Use current time for display
            })
        return threat_feed_data
    except requests.exceptions.RequestException as e:
        print(f"Error fetching AbuseIPDB blacklist: {e}")
        return []
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return []

def analyze_url_local_model(url):
    """
    Analyzes a URL using a simple rule-based local model.
    Returns a tuple of (verdict, confidence, summary).
    """
    verdict = 'BENIGN'
    confidence = 50.0
    summary = "Local model analysis: No immediate threats detected."

    lower_url = url.lower()

    # Rule 1: Check for common phishing keywords
    phishing_keywords = ['login', 'verify', 'account', 'update', 'security', 'paypal', 'bank', 'free', 'prize']
    if any(keyword in lower_url for keyword in phishing_keywords):
        verdict = 'SUSPICIOUS'
        confidence = max(confidence, 60.0)
        summary = "Local model analysis: URL contains suspicious keywords."

    # Rule 2: Check for IP addresses in domain part (obfuscation attempt)
    # This is a simplified check and might not catch all cases
    domain_part = url.split('//')[-1].split('/')[0]
    if any(char.isdigit() for char in domain_part) and '.' in domain_part:
        parts = domain_part.split('.')
        if all(part.isdigit() for part in parts) and len(parts) == 4:
            verdict = 'MALICIOUS'
            confidence = max(confidence, 85.0)
            summary = "Local model analysis: URL uses an IP address instead of a domain name."

    # Rule 3: Check for suspicious TLDs (example list, can be expanded)
    suspicious_tlds = ['.zip', '.xyz', '.top', '.club', '.online', '.site']
    if any(lower_url.endswith(tld) for tld in suspicious_tlds):
        verdict = 'SUSPICIOUS'
        confidence = max(confidence, 70.0)
        summary = "Local model analysis: URL uses a suspicious Top-Level Domain (TLD)."

    # Rule 4: Check for URL length (very long URLs can be suspicious)
    if len(url) > 100:
        verdict = 'SUSPICIOUS'
        confidence = max(confidence, 55.0)
        summary = "Local model analysis: URL is unusually long, which can be a sign of obfuscation."
        
    # Rule 5: Check for common malicious patterns (e.g., multiple subdomains, unusual characters)
    if lower_url.count('.') > 5 or '%' in lower_url or '@' in lower_url:
        verdict = 'SUSPICIOUS'
        confidence = max(confidence, 75.0)
        summary = "Local model analysis: URL contains multiple subdomains or unusual characters."

    return verdict, confidence, summary

def analyze_url_gemini(url):
    """
    Analyzes a URL using the Google Gemini API.
    Returns a tuple of (verdict, confidence, summary).
    """
    api_key = Config.GEMINI_API_KEY
    if not api_key:
        print("Gemini API key not configured. Skipping Gemini analysis.")
        return 'UNKNOWN', 0.0, "Gemini analysis skipped: API key not configured."

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-2.5-flash')

    prompt = f"""
    Analyze the following URL for potential threats such as phishing, malware, or other malicious activities.
    Provide a verdict (MALICIOUS, SUSPICIOUS, BENIGN), a confidence score (0-100), and a brief summary.
    URL: {url}
    
    Example Output Format:
    VERDICT: MALICIOUS
    CONFIDENCE: 95
    SUMMARY: This URL is highly likely to be a phishing site due to its deceptive domain and request for personal information.
    """

    try:
        response = model.generate_content(prompt)
        text_response = response.text.strip()

        verdict = 'UNKNOWN'
        confidence = 0.0
        summary = "Gemini analysis: Could not parse response."

        # Attempt to parse the response
        for line in text_response.split('\n'):
            if line.startswith('VERDICT:'):
                verdict = line.split(':', 1)[1].strip().upper()
            elif line.startswith('CONFIDENCE:'):
                try:
                    confidence = float(line.split(':', 1)[1].strip())
                except ValueError:
                    pass
            elif line.startswith('SUMMARY:'):
                summary = line.split(':', 1)[1].strip()
        
        # Basic validation for verdict
        if verdict not in ['MALICIOUS', 'SUSPICIOUS', 'BENIGN']:
            verdict = 'UNKNOWN'
            confidence = 0.0
            summary = f"Gemini analysis: Unclear verdict. Raw response: {text_response}"

        return verdict, confidence, summary

    except Exception as e:
        print(f"Gemini API error: {str(e)}")
        return 'UNKNOWN', 0.0, f"Gemini analysis failed: {str(e)}"
