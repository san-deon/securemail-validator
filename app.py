# pyrefly: ignore [missing-import]
from flask import Flask, render_template, request, jsonify
import re
from datetime import datetime
import difflib
import sqlite3

# Try to import dnspython
try:
    import dns.resolver
except ImportError:
    print("❌ ERROR: dnspython is not installed!")
    print("   Run: pip install dnspython")
    exit(1)

app = Flask(__name__)

# Database setup
DB_PATH = 'history.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS validations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            email TEXT,
            status TEXT,
            message TEXT,
            suggestion TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Initialize database
init_db()

# Common domains for typo suggestion
COMMON_DOMAINS = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
                 "icloud.com", "protonmail.com", "live.com", "msn.com", "gmx.com",
                 "googlemail.com", "yahoo.co.uk", "outlook.co.uk", "ymail.com"]

KNOWN_PROVIDERS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "ymail.com",
    "rocketmail.com", "hotmail.com", "outlook.com", "live.com", "msn.com",
    "aol.com", "icloud.com", "me.com", "protonmail.com"
}

DISPOSABLE_DOMAINS = {
    "10minutemail.com", "tempmail.com", "guerrillamail.com", "mailinator.com",
    "throwawaymail.com", "temp-mail.org", "yopmail.com", "sharklasers.com",
    "dispostable.com", "getairmail.com", "tempmailaddress.com", "maildrop.cc",
    "fakemail.net", "temporarymail.net", "trashmail.com", "mohmal.com"
}

def is_valid_format(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def get_domain(email):
    if '@' in email:
        return email.split('@')[1].lower().strip()
    return None

def check_domain_health(domain):
    try:
        try:
            mx_records = dns.resolver.resolve(domain, 'MX', lifetime=5)
            if mx_records:
                return {"valid": True, "level": "excellent", "message": "✅ Valid domain with mail servers"}
        except:
            pass

        try:
            a_records = dns.resolver.resolve(domain, 'A', lifetime=5)
            if a_records:
                return {"valid": True, "level": "good", "message": "⚠️ Domain exists but no MX records found"}
        except:
            pass

        try:
            aaaa_records = dns.resolver.resolve(domain, 'AAAA', lifetime=5)
            if aaaa_records:
                return {"valid": True, "level": "good", "message": "⚠️ Domain exists (IPv6) but no MX records"}
        except:
            pass

        return {"valid": False, "level": "poor", "message": "❌ Domain does not exist or has no mail configuration"}
    except:
        return {"valid": False, "level": "poor", "message": "❌ Could not verify domain"}

def get_smart_suggestion(domain):
    if not domain:
        return None
    matches = difflib.get_close_matches(domain, COMMON_DOMAINS, n=1, cutoff=0.75)
    return matches[0] if matches and matches[0] != domain else None

def save_to_db(result):
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''
        INSERT INTO validations (timestamp, email, status, message, suggestion)
        VALUES (?, ?, ?, ?, ?)
    ''', (
        result["timestamp"],
        result["email"],
        result.get("status"),
        result.get("message"),
        result.get("suggestion", "")
    ))
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/validate', methods=['POST'])
def validate_email():
    email = request.form.get('email', '').strip().lower()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
   
    result = {
        "email": email,
        "timestamp": timestamp,
        "status": "valid",
        "message": "✅ Email appears valid",
        "suggestion": None,
        "domain": None
    }

    if not email:
        result["status"] = "invalid"
        result["message"] = "❌ Email is required"
        save_to_db(result)
        return jsonify(result)

    if not is_valid_format(email):
        result["status"] = "invalid"
        result["message"] = "❌ Invalid email format"
        save_to_db(result)
        return jsonify(result)

    domain = get_domain(email)
    result["domain"] = domain

    if domain in DISPOSABLE_DOMAINS:
        result["status"] = "invalid"
        result["message"] = "❌ Disposable/Temporary email not allowed"
        save_to_db(result)
        return jsonify(result)

    suggestion = get_smart_suggestion(domain)
    if suggestion:
        result["status"] = "typo"
        result["message"] = f"⚠️ Possible typo - Did you mean {email.replace(domain, suggestion)}?"
        result["suggestion"] = email.replace(domain, suggestion)
        save_to_db(result)
        return jsonify(result)

    # Suspicious Provider Check
    if any(p in domain for p in ["yahoo", "gmail", "hotmail", "outlook", "aol"]):
        if domain not in KNOWN_PROVIDERS:
            result["status"] = "warning"
            provider = domain.split('.')[0].title()
            result["message"] = f"⚠️ Suspicious domain: {domain} is not an official {provider} email service"
            save_to_db(result)
            return jsonify(result)

    # Domain Health Check
    domain_health = check_domain_health(domain)
    result["message"] = domain_health["message"]
    if not domain_health["valid"]:
        result["status"] = "invalid"
    elif domain_health["level"] == "good":
        result["status"] = "warning"

    save_to_db(result)
    return jsonify(result)

@app.route('/history')
def get_history():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM validations ORDER BY id DESC LIMIT 20")
    rows = cursor.fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

@app.route('/clear_history', methods=['POST'])
def clear_history():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM validations")
    conn.commit()
    conn.close()
    return jsonify({"status": "success", "message": "✅ All history cleared successfully"})

if __name__ == '__main__':
    print("🚀 SecureMail Validator Started!")
    print("🌐 Open → http://127.0.0.1:5000")
    print("💾 History is now saved persistently")
    app.run(debug=True, host='127.0.0.1', port=5000)
