from app import create_app
from app.models import db

# Create the Flask application
try:
    app = create_app()
    print("Flask app created successfully!")
    
    # Test the app context
    with app.app_context():
        print("App context created successfully!")
        
        # Try to create the database tables
        db.create_all()
        print("Database tables created successfully!")
        
        # Check if routes are registered
        print("\nRegistered routes:")
        for rule in app.url_map.iter_rules():
            print(f"  {rule.rule} -> {rule.endpoint}")
    
    print("\nApplication setup is working correctly!")
    
except Exception as e:
    print(f"Error creating app: {e}")
    import traceback
    traceback.print_exc()