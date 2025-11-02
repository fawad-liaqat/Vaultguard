from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
def render_with_custom_css(template_name, **context):
    context['custom_css'] = url_for('static', filename='custom.css')
    return render_template(template_name, **context)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import re
import os
import secrets
from datetime import datetime, timedelta
from functools import wraps
import bleach
from cryptography.fernet import Fernet
import logging
from logging.handlers import RotatingFileHandler

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('logs', exist_ok=True)

if not app.debug:
    file_handler = RotatingFileHandler('logs/audit.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Secure FinTech App startup')

def init_db():
    conn = sqlite3.connect('fintech.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  email TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  full_name TEXT,
                  phone TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  login_attempts INTEGER DEFAULT 0,
                  locked_until TIMESTAMP,
                  is_active INTEGER DEFAULT 1)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS transactions
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  transaction_type TEXT NOT NULL,
                  amount REAL NOT NULL,
                  encrypted_description TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS audit_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  username TEXT,
                  action TEXT NOT NULL,
                  ip_address TEXT,
                  user_agent TEXT,
                  status TEXT,
                  details TEXT,
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    conn.commit()
    conn.close()

init_db()

def log_audit(user_id, username, action, status, details=''):
    try:
        conn = sqlite3.connect('fintech.db')
        c = conn.cursor()
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')[:200]
        
        c.execute('''INSERT INTO audit_logs 
                     (user_id, username, action, ip_address, user_agent, status, details)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (user_id, username, action, ip_address, user_agent, status, details))
        conn.commit()
        conn.close()
        
        app.logger.info(f'User: {username} | Action: {action} | Status: {status} | IP: {ip_address}')
    except Exception as e:
        app.logger.error(f'Audit logging error: {str(e)}')

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    return True, "Password is strong"

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def sanitize_input(text):
    if text is None:
        return ''
    return bleach.clean(str(text), tags=[], strip=True)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_with_custom_css('index.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per hour")
def register():
    if request.method == 'POST':
        try:
            username = sanitize_input(request.form.get('username', '').strip())
            email = sanitize_input(request.form.get('email', '').strip())
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')
            full_name = sanitize_input(request.form.get('full_name', '').strip())
            phone = sanitize_input(request.form.get('phone', '').strip())
            
            if not username or len(username) < 3:
                flash('Username must be at least 3 characters long', 'danger')
                return render_with_custom_css('register.html')
            
            if len(username) > 50:
                flash('Username is too long', 'danger')
                return render_with_custom_css('register.html')
            
            if not validate_email(email):
                flash('Invalid email format', 'danger')
                return render_with_custom_css('register.html')
            
            if password != confirm_password:
                flash('Passwords do not match', 'danger')
                return render_with_custom_css('register.html')
            
            is_valid, message = validate_password(password)
            if not is_valid:
                flash(message, 'danger')
                return render_with_custom_css('register.html')
            
            conn = sqlite3.connect('fintech.db')
            c = conn.cursor()
            c.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
            if c.fetchone():
                conn.close()
                flash('Username or email already exists', 'danger')
                log_audit(None, username, 'REGISTER_ATTEMPT', 'FAILED', 'Duplicate username/email')
                return render_with_custom_css('register.html')
            
            password_hash = generate_password_hash(password, method='pbkdf2:sha256')
            c.execute('''INSERT INTO users (username, email, password_hash, full_name, phone)
                         VALUES (?, ?, ?, ?, ?)''',
                      (username, email, password_hash, full_name, phone))
            conn.commit()
            user_id = c.lastrowid
            conn.close()
            
            log_audit(user_id, username, 'REGISTER', 'SUCCESS', f'New user registered: {email}')
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            app.logger.error(f'Registration error: {str(e)}')
            flash('An error occurred during registration', 'danger')
            return render_with_custom_css('register.html')
    
    return render_with_custom_css('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def login():
    if request.method == 'POST':
        try:
            username = sanitize_input(request.form.get('username', '').strip())
            password = request.form.get('password', '')
            
            if not username or not password:
                flash('Please provide both username and password', 'danger')
                return render_template('login.html')
            
            conn = sqlite3.connect('fintech.db')
            c = conn.cursor()
            c.execute('''SELECT id, username, password_hash, login_attempts, locked_until, is_active 
                         FROM users WHERE username = ?''', (username,))
            user = c.fetchone()
            
            if not user:
                conn.close()
                flash('Invalid username or password', 'danger')
                log_audit(None, username, 'LOGIN_ATTEMPT', 'FAILED', 'User not found')
                return render_template('login.html')
            
            user_id, db_username, password_hash, login_attempts, locked_until, is_active = user
            
            if locked_until:
                lock_time = datetime.strptime(locked_until, '%Y-%m-%d %H:%M:%S.%f')
                if datetime.now() < lock_time:
                    remaining = int((lock_time - datetime.now()).total_seconds() / 60)
                    flash(f'Account is locked. Try again in {remaining} minutes.', 'danger')
                    log_audit(user_id, username, 'LOGIN_ATTEMPT', 'FAILED', 'Account locked')
                    conn.close()
                    return render_template('login.html')
                else:
                    c.execute('UPDATE users SET login_attempts = 0, locked_until = NULL WHERE id = ?', (user_id,))
                    conn.commit()
            
            if not is_active:
                conn.close()
                flash('Account is disabled', 'danger')
                log_audit(user_id, username, 'LOGIN_ATTEMPT', 'FAILED', 'Account disabled')
                return render_template('login.html')
            
            if check_password_hash(password_hash, password):
                c.execute('UPDATE users SET login_attempts = 0, locked_until = NULL WHERE id = ?', (user_id,))
                conn.commit()
                conn.close()
                
                session.permanent = True
                session['user_id'] = user_id
                session['username'] = db_username
                session['login_time'] = datetime.now().isoformat()
                
                log_audit(user_id, username, 'LOGIN', 'SUCCESS', '')
                flash(f'Welcome back, {db_username}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                login_attempts += 1
                if login_attempts >= 5:
                    lock_time = datetime.now() + timedelta(minutes=15)
                    c.execute('UPDATE users SET login_attempts = ?, locked_until = ? WHERE id = ?',
                             (login_attempts, lock_time, user_id))
                    conn.commit()
                    conn.close()
                    flash('Too many failed attempts. Account locked for 15 minutes.', 'danger')
                    log_audit(user_id, username, 'LOGIN_ATTEMPT', 'FAILED', 'Account locked')
                else:
                    c.execute('UPDATE users SET login_attempts = ? WHERE id = ?', (login_attempts, user_id))
                    conn.commit()
                    conn.close()
                    remaining_attempts = 5 - login_attempts
                    flash(f'Invalid password. {remaining_attempts} attempts remaining.', 'danger')
                    log_audit(user_id, username, 'LOGIN_ATTEMPT', 'FAILED', 'Invalid password')
                
                return render_template('login.html')
                
        except Exception as e:
            app.logger.error(f'Login error: {str(e)}')
            flash('An error occurred during login', 'danger')
            return render_template('login.html')
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        conn = sqlite3.connect('fintech.db')
        c = conn.cursor()
        
        c.execute('SELECT username, email, full_name FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        
        c.execute('''SELECT id, transaction_type, amount, encrypted_description, created_at 
                     FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 5''',
                  (session['user_id'],))
        transactions = c.fetchall()
        
        decrypted_transactions = []
        for t in transactions:
            try:
                description = cipher_suite.decrypt(t[3].encode()).decode() if t[3] else ''
            except:
                description = 'Unable to decrypt'
            decrypted_transactions.append({
                'id': t[0],
                'type': t[1],
                'amount': t[2],
                'description': description,
                'date': t[4]
            })
        
        conn.close()
        
        log_audit(session['user_id'], session['username'], 'DASHBOARD_ACCESS', 'SUCCESS', '')
        
        return render_template('dashboard.html', 
                             user=user, 
                             transactions=decrypted_transactions)
    except Exception as e:
        app.logger.error(f'Dashboard error: {str(e)}')
        flash('An error occurred loading the dashboard', 'danger')
        return redirect(url_for('index'))

@app.route('/transaction', methods=['GET', 'POST'])
@login_required
def transaction():
    if request.method == 'POST':
        try:
            transaction_type = sanitize_input(request.form.get('transaction_type', ''))
            amount_str = request.form.get('amount', '')
            description = sanitize_input(request.form.get('description', ''))
            
            if transaction_type not in ['deposit', 'withdrawal', 'transfer']:
                flash('Invalid transaction type', 'danger')
                return render_template('transaction.html')
            
            try:
                amount = float(amount_str)
                if amount <= 0:
                    flash('Amount must be greater than 0', 'danger')
                    return render_template('transaction.html')
                if amount > 1000000:
                    flash('Amount exceeds maximum limit', 'danger')
                    return render_template('transaction.html')
            except ValueError:
                flash('Invalid amount', 'danger')
                return render_template('transaction.html')
            
            encrypted_description = cipher_suite.encrypt(description.encode()).decode()
            
            conn = sqlite3.connect('fintech.db')
            c = conn.cursor()
            c.execute('''INSERT INTO transactions (user_id, transaction_type, amount, encrypted_description)
                         VALUES (?, ?, ?, ?)''',
                      (session['user_id'], transaction_type, amount, encrypted_description))
            conn.commit()
            conn.close()
            
            log_audit(session['user_id'], session['username'], 'TRANSACTION_CREATE', 'SUCCESS',
                     f'Type: {transaction_type}, Amount: {amount}')
            
            flash('Transaction recorded successfully', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            app.logger.error(f'Transaction error: {str(e)}')
            flash('An error occurred', 'danger')
            return render_template('transaction.html')
    
    return render_template('transaction.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        try:
            full_name = sanitize_input(request.form.get('full_name', '').strip())
            phone = sanitize_input(request.form.get('phone', '').strip())
            email = sanitize_input(request.form.get('email', '').strip())
            
            if not validate_email(email):
                flash('Invalid email format', 'danger')
                return redirect(url_for('profile'))
            
            if len(full_name) > 100:
                flash('Full name is too long', 'danger')
                return redirect(url_for('profile'))
            
            conn = sqlite3.connect('fintech.db')
            c = conn.cursor()
            c.execute('SELECT id FROM users WHERE email = ? AND id != ?', 
                     (email, session['user_id']))
            if c.fetchone():
                conn.close()
                flash('Email is already in use', 'danger')
                return redirect(url_for('profile'))
            
            c.execute('''UPDATE users SET full_name = ?, phone = ?, email = ? 
                         WHERE id = ?''',
                      (full_name, phone, email, session['user_id']))
            conn.commit()
            conn.close()
            
            log_audit(session['user_id'], session['username'], 'PROFILE_UPDATE', 'SUCCESS', '')
            flash('Profile updated successfully', 'success')
            return redirect(url_for('profile'))
            
        except Exception as e:
            app.logger.error(f'Profile update error: {str(e)}')
            flash('An error occurred', 'danger')
            return redirect(url_for('profile'))
    
    try:
        conn = sqlite3.connect('fintech.db')
        c = conn.cursor()
        c.execute('SELECT username, email, full_name, phone, created_at FROM users WHERE id = ?',
                 (session['user_id'],))
        user = c.fetchone()
        conn.close()
        
        return render_template('profile.html', user=user)
    except Exception as e:
        app.logger.error(f'Profile view error: {str(e)}')
        flash('An error occurred', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        try:
            if 'file' not in request.files:
                flash('No file selected', 'danger')
                return render_template('upload.html')
            
            file = request.files['file']
            
            if file.filename == '':
                flash('No file selected', 'danger')
                return render_template('upload.html')
            
            if not allowed_file(file.filename):
                flash(f'Invalid file type. Allowed: {", ".join(ALLOWED_EXTENSIONS)}', 'danger')
                log_audit(session['user_id'], session['username'], 'FILE_UPLOAD', 'FAILED',
                         f'Invalid type: {file.filename}')
                return render_template('upload.html')
            
            filename = secure_filename(file.filename)
            name, ext = os.path.splitext(filename)
            unique_filename = f"{session['user_id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{name}{ext}"
            
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(filepath)
            
            log_audit(session['user_id'], session['username'], 'FILE_UPLOAD', 'SUCCESS',
                     f'File: {unique_filename}')
            
            flash(f'File {filename} uploaded successfully', 'success')
            return redirect(url_for('upload'))
            
        except Exception as e:
            app.logger.error(f'Upload error: {str(e)}')
            flash('An error occurred', 'danger')
            return render_template('upload.html')
    
    return render_template('upload.html')

@app.route('/audit_logs')
@login_required
def audit_logs():
    try:
        conn = sqlite3.connect('fintech.db')
        c = conn.cursor()
        c.execute('''SELECT action, status, details, timestamp 
                     FROM audit_logs WHERE user_id = ? 
                     ORDER BY timestamp DESC LIMIT 50''',
                  (session['user_id'],))
        logs = c.fetchall()
        conn.close()
        
        log_audit(session['user_id'], session['username'], 'AUDIT_LOG_VIEW', 'SUCCESS', '')
        
        return render_template('audit_logs.html', logs=logs)
    except Exception as e:
        app.logger.error(f'Audit logs error: {str(e)}')
        flash('An error occurred', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    username = session.get('username', 'Unknown')
    user_id = session.get('user_id')
    
    log_audit(user_id, username, 'LOGOUT', 'SUCCESS', '')
    
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', 
                         error_code=404, 
                         error_message='Page Not Found'), 404

@app.errorhandler(500)
def internal_error(e):
    app.logger.error(f'Internal error: {str(e)}')
    return render_template('error.html', 
                         error_code=500, 
                         error_message='Internal Server Error'), 500

@app.before_request
def check_session_timeout():
    if 'user_id' in session:
        login_time_str = session.get('login_time')
        if login_time_str:
            login_time = datetime.fromisoformat(login_time_str)
            if datetime.now() - login_time > timedelta(minutes=15):
                session.clear()
                flash('Session expired. Please log in again.', 'warning')
                return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)