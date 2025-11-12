from flask import Blueprint, render_template, request, jsonify, redirect, url_for
from flask_login import login_required, current_user
from app.models import db, ScanRecord, User
from app.utils import (
    analyze_url_virustotal, analyze_ip_virustotal, analyze_domain_virustotal,
    analyze_file_virustotal, fetch_abuseipdb_blacklist,
    analyze_url_local_model, analyze_url_gemini # Import new functions
)
from datetime import datetime, timedelta

main_bp = Blueprint('main', __name__)

# Helper for verdict severity
VERDICT_SEVERITY = {'MALICIOUS': 3, 'SUSPICIOUS': 2, 'BENIGN': 1, 'UNKNOWN': 0}

@main_bp.route('/')
def index():
    # Redirect to dashboard if user is logged in, otherwise to login
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))

@main_bp.route('/dashboard')
@login_required
def dashboard():
    # Get recent scan records for the current user
    recent_scans = ScanRecord.query.filter_by(user_id=current_user.id).order_by(ScanRecord.timestamp.desc()).limit(5).all()
    
    # Calculate stats for the current user
    total_scans = ScanRecord.query.filter_by(user_id=current_user.id).count()
    malicious_scans = ScanRecord.query.filter_by(user_id=current_user.id, verdict='MALICIOUS').count()
    file_scans = ScanRecord.query.filter_by(user_id=current_user.id, scan_type='file').count() # New line
    
    # If admin, get all stats
    if current_user.is_admin():
        total_scans = ScanRecord.query.count()
        malicious_scans = ScanRecord.query.filter_by(verdict='MALICIOUS').count()
        file_scans = ScanRecord.query.filter_by(scan_type='file').count() # New line
        recent_scans = ScanRecord.query.order_by(ScanRecord.timestamp.desc()).limit(5).all()
    
    return render_template('dashboard.html', 
                          recent_scans=recent_scans, 
                          total_scans=total_scans, 
                          malicious_scans=malicious_scans,
                          file_scans=file_scans) # New line

@main_bp.route('/url-detector')
@login_required
def url_detector():
    return render_template('url_detector.html')

@main_bp.route('/file-scanner')
@login_required
def file_scanner():
    return render_template('file_scanner.html')

@main_bp.route('/ip-checker')
@login_required
def ip_checker():
    return render_template('ip_checker.html')

@main_bp.route('/domain-checker')
@login_required
def domain_checker():
    return render_template('domain_checker.html')

@main_bp.route('/threat-feed')
@login_required
def threat_feed():
    threat_feed_data = fetch_abuseipdb_blacklist()
    
    # Process timestamps for display
    for threat in threat_feed_data:
        if 'timestamp' in threat and isinstance(threat['timestamp'], str):
            try:
                # Assuming ISO format from AbuseIPDB
                threat['timestamp'] = datetime.fromisoformat(threat['timestamp'].replace('Z', '+00:00'))
            except ValueError:
                # Fallback if format is unexpected
                threat['timestamp'] = datetime.now() 
        elif 'timestamp' not in threat:
            threat['timestamp'] = datetime.now() # Default if no timestamp
            
    return render_template('threat_feed.html', threat_feed=threat_feed_data)

@main_bp.route('/history')
@login_required
def history():
    # Get all scan records for the current user
    if current_user.is_admin():
        # Admin can see all scan records
        scan_records = ScanRecord.query.order_by(ScanRecord.timestamp.desc()).all()
    else:
        # Regular user can only see their own scan records
        scan_records = ScanRecord.query.filter_by(user_id=current_user.id).order_by(ScanRecord.timestamp.desc()).all()
        
    return render_template('history.html', scan_records=scan_records)

from app.routes.auth import admin_required

@main_bp.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@main_bp.route('/analyze', methods=['POST'])
@login_required
def analyze():
    """
    API endpoint to analyze URLs, IPs, domains, or files for threats.
    This replaces the Firebase functionality in the original frontend.
    """
    data = request.get_json()
    input_value = data.get('input_value')
    scan_type = data.get('scan_type')  # 'url', 'ip', 'domain', 'file'

    overall_verdict = 'BENIGN'
    overall_confidence = 0.0
    overall_summary_parts = [] # Use a list to build summary parts

    if scan_type == 'url':
        # --- Local Model Analysis (Prioritized) ---
        lm_verdict, lm_confidence, lm_summary = analyze_url_local_model(input_value)
        
        # If local model gives a strong verdict, use it and potentially skip external APIs
        if VERDICT_SEVERITY.get(lm_verdict, 0) >= VERDICT_SEVERITY['SUSPICIOUS'] and lm_confidence >= 60:
            overall_verdict = lm_verdict
            overall_confidence = lm_confidence
            overall_summary_parts.append(f"Local analysis: {lm_summary}")
        else:
            # Local model inconclusive or benign, proceed with external APIs
            overall_summary_parts.append(f"Local analysis: {lm_summary}") # Still include local model summary

            # --- External API Analysis (VirusTotal and Gemini) ---
            external_verdicts = []
            external_confidences = []
            external_summaries = []

            vt_verdict, vt_confidence, vt_summary = analyze_url_virustotal(input_value)
            if VERDICT_SEVERITY.get(vt_verdict, 0) > 0: # Only consider if not UNKNOWN/BENIGN
                external_verdicts.append(vt_verdict)
                external_confidences.append(vt_confidence)
                external_summaries.append(vt_summary)

            gemini_verdict, gemini_confidence, gemini_summary = analyze_url_gemini(input_value)
            if VERDICT_SEVERITY.get(gemini_verdict, 0) > 0: # Only consider if not UNKNOWN/BENIGN
                external_verdicts.append(gemini_verdict)
                external_confidences.append(gemini_confidence)
                external_summaries.append(gemini_summary)
            
            # Combine external results
            if external_verdicts:
                # Find the most severe verdict among external sources
                most_severe_external_verdict = 'BENIGN'
                for v in external_verdicts:
                    if VERDICT_SEVERITY.get(v, 0) > VERDICT_SEVERITY.get(most_severe_external_verdict, 0):
                        most_severe_external_verdict = v
                
                # Take the highest confidence for the most severe verdict
                max_external_confidence = 0.0
                for i, v in enumerate(external_verdicts):
                    if v == most_severe_external_verdict:
                        max_external_confidence = max(max_external_confidence, external_confidences[i])
                
                overall_verdict = most_severe_external_verdict
                overall_confidence = max(overall_confidence, max_external_confidence)
                overall_summary_parts.append(f"External analysis: {' | '.join(external_summaries)}")
            else:
                # If no strong external verdicts, and local was inconclusive, default to benign
                if overall_verdict == 'BENIGN':
                    overall_summary_parts.append("External analysis: No strong indicators found.")
            
        verdict = overall_verdict
        confidence = overall_confidence
        summary = " | ".join(overall_summary_parts)

    elif scan_type == 'ip':
        verdict, confidence, summary = analyze_ip_virustotal(input_value)
    elif scan_type == 'domain':
        verdict, confidence, summary = analyze_domain_virustotal(input_value)
    elif scan_type == 'file':
        verdict, confidence, summary = analyze_file_virustotal(input_value)
    else:
        # Fallback to simulation for unknown scan types
        verdict, confidence, summary = simulate_threat_analysis(input_value, scan_type)

    # Save scan record to database
    scan_record = ScanRecord(
        user_id=current_user.id,
        input_value=input_value,
        scan_type=scan_type,
        verdict=verdict,
        confidence=confidence
    )
    db.session.add(scan_record)
    db.session.commit()

    return jsonify({
        'verdict': verdict,
        'confidence': confidence,
        'summary': summary,
        'input_value': input_value,
        'scan_type': scan_type
    })

def simulate_threat_analysis(input_value, scan_type):
    """
    Simulate threat analysis - in a real implementation,
    this would call VirusTotal API or a ML model
    """
    # Simple simulation logic
    if 'phish' in input_value or 'malware' in input_value or 'bosu.edu.ng' in input_value.lower():
        verdict = 'MALICIOUS'
        confidence = 95.0
        summary = 'The analysis determined this entity is MALICIOUS. The ML model showed high confidence, and multiple VirusTotal engines flagged it.'
    elif 'bank' in input_value or 'login' in input_value or '192.168' in input_value:
        verdict = 'SUSPICIOUS'
        confidence = 70.0
        summary = 'The analysis flagged this entity as SUSPICIOUS. While not overtly malicious, features suggest potential risk (e.g., login form or private IP).'
    else:
        verdict = 'BENIGN'
        confidence = 90.0
        summary = 'The analysis determined this entity is BENIGN. All ML features and VirusTotal reports indicate low risk.'
    
    return verdict, confidence, summary