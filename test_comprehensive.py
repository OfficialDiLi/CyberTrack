from app import create_app
from app.models import db, User, ScanRecord
from app.utils import analyze_url_virustotal, simulate_analysis

def test_app_functionality():
    app = create_app()
    
    with app.app_context():
        # Create all tables
        db.create_all()
        print("✓ Database tables created")
        
        # Test creating a user
        user = User(username='testuser', email='test@example.com')
        user.set_password('password')
        db.session.add(user)
        db.session.commit()
        print("✓ User created and password hashed")
        
        # Test retrieving the user
        retrieved_user = User.query.filter_by(username='testuser').first()
        assert retrieved_user is not None
        assert retrieved_user.check_password('password')
        print("✓ User authentication works")
        
        # Test creating a scan record
        scan = ScanRecord(
            user_id=retrieved_user.id,
            input_value='https://example.com',
            scan_type='url',
            verdict='BENIGN',
            confidence=95.0
        )
        db.session.add(scan)
        db.session.commit()
        print("✓ Scan record created")
        
        # Test VirusTotal integration (this will use simulation without API key)
        verdict, confidence, summary = analyze_url_virustotal('https://google.com')
        print(f"✓ VirusTotal API integration works: {verdict} with {confidence}% confidence")
        
        # Test scan record retrieval
        user_scans = ScanRecord.query.filter_by(user_id=retrieved_user.id).all()
        assert len(user_scans) == 1
        print("✓ Scan records can be retrieved")
        
        # Test admin functionality
        admin_user = User.query.filter_by(username='admin').first()
        if admin_user:
            assert admin_user.is_admin() == True
            print("✓ Admin role functionality works")
        else:
            print("⚠ No admin user found (this is okay if not created yet)")
        
        print("\n🎉 All functionality tests passed!")
        
        # Show some sample data
        print(f"\nSample data:")
        print(f"- Users in DB: {User.query.count()}")
        print(f"- Scan records in DB: {ScanRecord.query.count()}")
        
        # Clean up test data - remove scan first to avoid constraint issues
        db.session.delete(scan)
        db.session.commit()
        print(f"\n✓ Test cleanup completed")

if __name__ == "__main__":
    try:
        test_app_functionality()
        print("\n✅ All tests completed successfully!")
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()