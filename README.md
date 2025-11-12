# Cybersecurity Threat Detection Platform

A Flask-based web application for detecting and analyzing cybersecurity threats using both machine learning models and VirusTotal API integration.

## Features

- **User Authentication**: Secure login/registration system with role-based access control (admin/user)
- **Threat Detection**: Analyze URLs, IPs, domains, and file hashes for potential threats
- **Database Integration**: SQLAlchemy ORM with support for SQLite, MySQL, and PostgreSQL
- **VirusTotal API**: Real-time threat analysis using VirusTotal API (with fallback simulation)
- **Admin Panel**: Admin users can view all system users and their activities
- **Dashboard**: Overview of security metrics and recent activity
- **Scan History**: Track and review previous threat analysis results

## Tech Stack

- **Backend**: Flask (Python 3.11+)
- **Database**: SQLAlchemy with support for SQLite, MySQL, PostgreSQL
- **Authentication**: Flask-Login with password hashing using Werkzeug
- **Frontend**: Jinja2 templates with Tailwind CSS and Material Icons
- **API Integration**: VirusTotal API for threat intelligence

## Installation

1. Clone the repository
2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Set up environment variables (optional but recommended):
   ```bash
   export VIRUSTOTAL_API_KEY="your_virustotal_api_key_here"
   export SECRET_KEY="your_secret_key_here"
   ```

## Usage

1. Run the application:
   ```bash
   python main.py
   ```
2. Visit http://localhost:5000 in your browser
3. Use the default admin credentials to log in:
   - Username: `admin`
   - Password: `admin123`

## Configuration

The application can be configured using environment variables or by modifying `app/config.py`:

- `VIRUSTOTAL_API_KEY`: Your VirusTotal API key for real threat analysis
- `SECRET_KEY`: Flask secret key for session management
- `DATABASE_URL`: Database connection string (defaults to SQLite)

## Application Structure

```
app/
├── __init__.py          # Application factory with Flask-Login user_loader
├── app.py              # Application factory pattern (deprecated, now in __init__.py)
├── config.py           # Configuration settings
├── models.py           # SQLAlchemy models (User, ScanRecord)
├── utils.py            # Utility functions (VirusTotal API integration)
├── routes/
│   ├── auth.py         # Authentication routes (login, register, logout)
│   └── main.py         # Main application routes
├── static/             # Static assets (CSS, JS, icons)
└── templates/          # Jinja2 templates
```

## Database Models

- **User**: Stores user information with username, email, hashed password, and role (user/admin)
- **ScanRecord**: Stores threat analysis results with input value, scan type, verdict, and confidence

## API Endpoints

- `POST /analyze`: Analyze a URL, IP, domain, or file hash for threats
- `GET /dashboard`: User dashboard with security metrics
- `GET /admin/users`: Admin panel to view all users (admin only)

## Security Features

- Passwords are hashed using Werkzeug's secure hashing
- Session management using Flask-Login
- Role-based access controls for admin functionality
- Input validation and sanitization

## VirusTotal Integration

The application integrates with the VirusTotal API for real-time threat intelligence. When an API key is provided, the application will:
1. Submit the input (URL, IP, domain, or file hash) to VirusTotal
2. Retrieve analysis results from security vendors
3. Calculate a confidence score based on the number of vendors flagging the input as malicious

If no API key is provided, the application falls back to simulated analysis results.

## Customization

To customize the application for your environment:

1. Update `app/config.py` with your preferred settings
2. Modify templates in the `templates/` directory to change the UI
3. Add new analysis functions in `app/utils.py`
4. Extend the models in `app/models.py` as needed