from app import create_app
from app.models import db, User, ScanRecord

app = create_app()

# Create tables
with app.app_context():
    db.create_all()
    
    # Create a default admin user if one doesn't exist
    # For production, create users via a secure method (e.g., CLI command or registration page)
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        admin_user = User(username='admin', email='admin@security-platform.com', role='admin')
        admin_user.set_password('admin123')  # Change this in production!
        db.session.add(admin_user)
        db.session.commit()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
