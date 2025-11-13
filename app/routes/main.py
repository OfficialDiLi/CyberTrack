from flask import Blueprint, render_template, request, jsonify, redirect, url_for
from flask_login import login_required, current_user
from app.models import db, ScanRecord, User
from app.utils import (
    analyze_url_virustotal, analyze_ip_abuseipdb, analyze_domain_virustotal,
    analyze_file_virustotal, fetch_abuseipdb_blacklist,
    analyze_url_local_model, analyze_url_gemini, simulate_analysis, analyze_domain_whois
)
from datetime import datetime

main_bp = Blueprint('main', __name__)

VERDICT_SEVERITY = {'MALICIOUS': 3, 'SUSPICIOUS': 2, 'BENIGN': 1, 'UNKNOWN': 0}

@main_bp.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))

@main_bp.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin():
        recent_scans = ScanRecord.query.order_by(ScanRecord.timestamp.desc()).limit(5).all()
        total_scans = ScanRecord.query.count()
        malicious_scans = ScanRecord.query.filter_by(verdict='MALICIOUS').count()
        file_scans = ScanRecord.query.filter_by(scan_type='file').count()
    else:
        recent_scans = ScanRecord.query.filter_by(user_id=current_user.id).order_by(ScanRecord.timestamp.desc()).limit(5).all()
        total_scans = ScanRecord.query.filter_by(user_id=current_user.id).count()
        malicious_scans = ScanRecord.query.filter_by(user_id=current_user.id, verdict='MALICIOUS').count()
        file_scans = ScanRecord.query.filter_by(user_id=current_user.id, scan_type='file').count()
    
    return render_template('dashboard.html', 
                          recent_scans=recent_scans, 
                          total_scans=total_scans, 
                          malicious_scans=malicious_scans,
                          file_scans=file_scans)

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
    for threat in threat_feed_data:
        if 'timestamp' in threat and isinstance(threat['timestamp'], str):
            try:
                threat['timestamp'] = datetime.fromisoformat(threat['timestamp'].replace('Z', '+00:00'))
            except ValueError:
                threat['timestamp'] = datetime.now() 
    return render_template('threat_feed.html', threat_feed=threat_feed_data)

@main_bp.route('/history')
@login_required
def history():
    if current_user.is_admin():
        scan_records = ScanRecord.query.order_by(ScanRecord.timestamp.desc()).all()
    else:
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
    data = request.get_json()
    input_value = data.get('input_value')
    scan_type = data.get('scan_type')

    sources = []
    if scan_type == 'url':
        sources.append(analyze_url_local_model(input_value))
        sources.append(analyze_url_virustotal(input_value))
        sources.append(analyze_url_gemini(input_value))
    elif scan_type == 'ip':
        sources.append(analyze_ip_abuseipdb(input_value))
    elif scan_type == 'domain':
        sources.append(analyze_domain_virustotal(input_value))
        sources.append(analyze_domain_whois(input_value))
    elif scan_type == 'file':
        sources.append(analyze_file_virustotal(input_value))
    else:
        sources.append(simulate_analysis(input_value, scan_type))

    overall_verdict = 'BENIGN'
    overall_confidence = 0.0
    highest_severity = 0

    for source in sources:
        severity = VERDICT_SEVERITY.get(source['verdict'], 0)
        if severity > highest_severity:
            highest_severity = severity
            overall_verdict = source['verdict']
            overall_confidence = source['confidence']

    summary_parts = [f"{s['source']}: {s['summary']}" for s in sources]
    overall_summary = " | ".join(summary_parts)

    scan_record = ScanRecord(
        user_id=current_user.id,
        input_value=input_value,
        scan_type=scan_type,
        verdict=overall_verdict,
        confidence=overall_confidence
    )
    db.session.add(scan_record)
    db.session.commit()

    return jsonify({
        'input_value': input_value,
        'scan_type': scan_type,
        'verdict': overall_verdict,
        'confidence': overall_confidence,
        'summary': overall_summary,
        'sources': sources
    })
