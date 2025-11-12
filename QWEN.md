## 🧩 Project Transition Plan — Frontend → Flask Full-stack

### 🎯 Objective

Transform the static HTML/JS frontend into a **Flask web application** with:

* Backend-rendered templates (`Jinja2`) for modular pages.
* Database-driven authentication (users + admins).
* Support for multiple database engines via SQLAlchemy.
* Secure session management with Flask-Login.
* API endpoints for frontend threat analysis interaction.



### ⚙️ Backend Tech Stack

| Component            | Technology                              |
| -------------------- | --------------------------------------- |
| **Framework**        | Flask (Python 3.11+)                    |
| **ORM**              | SQLAlchemy                              |
| **Auth**             | Flask-Login + Werkzeug password hashing |
| **Database Engines** | SQLite (dev), MySQL / PostgreSQL (prod) |
| **API Integration**  | VirusTotal API (via `requests` module)  |
| **Template Engine**  | Jinja2                                  |
| **Styling**          | Tailwind CSS (linked from CDN)          |
| **Icons**            | Material Icons                          |



### 🔐 Authentication and Authorization

We’ll have **two user roles**:

1. **Admin** — can view all users, threat logs, system analytics.
2. **Regular User** — can run scans, view personal scan history only.

#### Implementation Highlights:

* Use `Flask-Login` for sessions.
* Store user roles in the `User` table (column: `role` = `'admin' | 'user'`).
* Protect routes with decorators:

  ```python
  @login_required
  @roles_required('admin')
  def admin_dashboard():
      ...
  ```
* Hash passwords with `generate_password_hash()`.



### 🧱 Database Schema (SQLAlchemy Models)

```python
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), default='user')  # 'admin' or 'user'

class ScanRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    input_value = db.Column(db.String(255))
    scan_type = db.Column(db.String(50))  # URL, IP, File, etc.
    verdict = db.Column(db.String(50))
    confidence = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
```

SQLAlchemy’s engine flexibility ensures support for:

```python
SQLALCHEMY_DATABASE_URI = {
    "sqlite": "sqlite:///security_platform.db",
    "mysql": "mysql+pymysql://user:pass@localhost/security_platform",
    "postgres": "postgresql://user:pass@localhost/security_platform"
}
```



### 🖼️ Frontend Integration into Flask

We’ll:

* Move static assets (`Tailwind`, `Material Icons`, `app.js`) into `/static`.
* Convert `index.html` into modular Jinja2 templates:

  * `base.html` (layout)
  * `dashboard.html`
  * `url_detector.html`, etc.
* Replace Firebase logic with Flask routes and RESTful endpoints:

  ```python
  @app.route('/analyze', methods=['POST'])
  def analyze():
      data = request.json
      return jsonify(verdict="MALICIOUS", confidence=99.2)
  ```



### 🧠 Now — the Updated `QWEN.md`

Here’s the new project-aware Qwen config file to guide your development session with Qwen Code:




### 🏗️ Project Context

Migration of a static **cybersecurity dashboard frontend** from /docs/index.html into a **Flask web application** with secure user management and multi-database backend support.
The platform allows scanning of URLs, IPs, domains, and files for threats using the VirusTotal API and ML integration.



### 🧰 Development Stack

* **Backend:** Flask, SQLAlchemy, Flask-Login
* **Databases:** SQLite (dev), MySQL, PostgreSQL
* **Frontend:** HTML, Tailwind CSS, Material Icons, JS (with fetch API)
* **API:** VirusTotal (REST integration)
* **Auth:** Flask-Login (Sessions + Role-based Access)



### 🧭 Core Modules

| Module        | Purpose                                                 |
| ------------- | ------------------------------------------------------- |
| `/auth/`      | Handles login, logout, register, and admin controls.    |
| `/routes/`    | Handles Flask route definitions and logic.              |
| `/models.py`  | SQLAlchemy models (User, ScanRecord).                   |
| `/templates/` | Jinja2 templates derived from the current `index.html`. |
| `/static/`    | Contains Tailwind CSS, JS, icons.                       |

---

### 🔐 Auth Requirements

* Users authenticate via `/login`.
* Passwords hashed using Werkzeug.
* Flask-Login maintains session.
* Admin dashboard protected via role-based decorator.
* JWTs optional for REST API endpoints.

---

### 🧩 Frontend Behavior

* Dashboard, URL Detector, File Scanner, IP Checker, Domain Checker, Threat Feed, History.
* Uses `fetch('/api/analyze', {...})` for backend communication.
* No Firebase — replaced with server endpoints.
* Retain current Tailwind visual hierarchy.
* Maintain accessibility and responsive design.


### 🧠 Qwen Interaction Rules

* Qwen should generate **Flask code** compatible with Python 3.11+.
* Use **SQLAlchemy ORM** (not raw SQL).
* Provide **Jinja2 templates** for HTML views.
* Write modular, production-ready code with docstrings and inline comments.
* Ensure generated code runs with any of SQLite/MySQL/PostgreSQL.
* Always include environment variable usage for sensitive configs (e.g., DB credentials).
* When creating auth logic, enforce secure password handling and CSRF protection.



### 📂 Flask Folder Structure

```
app/
├── app.py
├── config.py
├── models.py
├── routes/
│   ├── auth.py
│   └── main.py
├── templates/
│   ├── base.html
│   ├── dashboard.html
│   ├── login.html
│   ├── register.html
│   └── scan_result.html
├── static/
│   ├── css/
│   ├── js/
│   └── icons/
└── 
/QWEN.md
```

