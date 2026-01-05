#!/usr/bin/env python3
"""
Zon Productions Download Portal
Gated download system for NightShadow
"""
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, abort
from functools import wraps
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

# Load .env if exists
env_path = Path(__file__).parent / '.env'
if env_path.exists():
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                os.environ[key.strip()] = value.strip()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'change-this-in-production')

# Config
DATABASE = Path(__file__).parent / 'users.db'
DOWNLOADS_DIR = Path(__file__).parent / 'downloads'
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@zon-productions.com')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'changeme')

# Game info
GAME_NAME = "NightShadow"
COMPANY_NAME = "Zon Productions"
GAME_FILE = os.environ.get('GAME_FILE', 'NightShadow.zip')  # Filename in downloads folder


# ============================================
# DATABASE
# ============================================

def get_db():
    """Get database connection."""
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    """Initialize database."""
    db = get_db()
    db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            username TEXT NOT NULL,
            approved INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    db.commit()
    db.close()
    print("Database initialized")


# Initialize on startup
DOWNLOADS_DIR.mkdir(exist_ok=True)
init_db()


# ============================================
# AUTH DECORATORS
# ============================================

def login_required(f):
    """Require user login."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated


def approved_required(f):
    """Require approved user."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login', next=request.url))
        if not session.get('approved'):
            flash('Your account is pending approval.', 'error')
            return redirect(url_for('pending'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Require admin login."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('is_admin'):
            flash('Admin access required.', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated


# ============================================
# PUBLIC ROUTES
# ============================================

@app.route('/')
def index():
    """Landing page."""
    return render_template('index.html', 
                          game_name=GAME_NAME, 
                          company_name=COMPANY_NAME)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration."""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')
        
        errors = []
        if not email or '@' not in email:
            errors.append('Valid email required')
        if not username or len(username) < 2:
            errors.append('Username required (min 2 characters)')
        if not password or len(password) < 6:
            errors.append('Password required (min 6 characters)')
        if password != confirm:
            errors.append('Passwords do not match')
        
        if errors:
            for e in errors:
                flash(e, 'error')
            return render_template('register.html', 
                                  email=email, 
                                  username=username,
                                  game_name=GAME_NAME,
                                  company_name=COMPANY_NAME)
        
        # Check if email exists
        db = get_db()
        existing = db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
        if existing:
            flash('Email already registered', 'error')
            db.close()
            return render_template('register.html', 
                                  email=email, 
                                  username=username,
                                  game_name=GAME_NAME,
                                  company_name=COMPANY_NAME)
        
        # Create user
        password_hash = generate_password_hash(password)
        db.execute('INSERT INTO users (email, password_hash, username) VALUES (?, ?, ?)',
                  (email, password_hash, username))
        db.commit()
        db.close()
        
        flash('Registration successful! Please wait for admin approval.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html',
                          game_name=GAME_NAME,
                          company_name=COMPANY_NAME)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login."""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        db.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['email'] = user['email']
            session['approved'] = bool(user['approved'])
            
            if user['approved']:
                next_url = request.args.get('next', url_for('download'))
                return redirect(next_url)
            else:
                return redirect(url_for('pending'))
        
        flash('Invalid email or password', 'error')
    
    return render_template('login.html',
                          game_name=GAME_NAME,
                          company_name=COMPANY_NAME)


@app.route('/logout')
def logout():
    """User logout."""
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))


@app.route('/pending')
@login_required
def pending():
    """Pending approval page."""
    if session.get('approved'):
        return redirect(url_for('download'))
    return render_template('pending.html',
                          game_name=GAME_NAME,
                          company_name=COMPANY_NAME)


# ============================================
# DOWNLOAD ROUTES
# ============================================

@app.route('/download')
@approved_required
def download():
    """Download page for approved users."""
    # Check if game file exists
    game_path = DOWNLOADS_DIR / GAME_FILE
    file_exists = game_path.exists()
    file_size = None
    if file_exists:
        size_bytes = game_path.stat().st_size
        file_size = f"{size_bytes / (1024**3):.2f} GB" if size_bytes > 1024**3 else f"{size_bytes / (1024**2):.0f} MB"
    
    return render_template('download.html',
                          game_name=GAME_NAME,
                          company_name=COMPANY_NAME,
                          game_file=GAME_FILE,
                          file_exists=file_exists,
                          file_size=file_size)


@app.route('/download/file')
@approved_required
def download_file():
    """Serve the game file."""
    game_path = DOWNLOADS_DIR / GAME_FILE
    if not game_path.exists():
        abort(404)
    
    return send_from_directory(DOWNLOADS_DIR, GAME_FILE, as_attachment=True)


# ============================================
# ADMIN ROUTES
# ============================================

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login."""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        if email == ADMIN_EMAIL.lower() and password == ADMIN_PASSWORD:
            session['is_admin'] = True
            session['admin_email'] = email
            return redirect(url_for('admin_dashboard'))
        
        flash('Invalid admin credentials', 'error')
    
    return render_template('admin_login.html',
                          game_name=GAME_NAME,
                          company_name=COMPANY_NAME)


@app.route('/admin/logout')
def admin_logout():
    """Admin logout."""
    session.pop('is_admin', None)
    session.pop('admin_email', None)
    flash('Admin logged out.', 'success')
    return redirect(url_for('index'))


@app.route('/admin')
@admin_required
def admin_dashboard():
    """Admin dashboard - manage users."""
    db = get_db()
    pending_users = db.execute(
        'SELECT * FROM users WHERE approved = 0 ORDER BY created_at DESC'
    ).fetchall()
    approved_users = db.execute(
        'SELECT * FROM users WHERE approved = 1 ORDER BY created_at DESC'
    ).fetchall()
    db.close()
    
    # Check game file
    game_path = DOWNLOADS_DIR / GAME_FILE
    file_exists = game_path.exists()
    file_size = None
    if file_exists:
        size_bytes = game_path.stat().st_size
        file_size = f"{size_bytes / (1024**3):.2f} GB" if size_bytes > 1024**3 else f"{size_bytes / (1024**2):.0f} MB"
    
    return render_template('admin.html',
                          game_name=GAME_NAME,
                          company_name=COMPANY_NAME,
                          pending_users=pending_users,
                          approved_users=approved_users,
                          game_file=GAME_FILE,
                          file_exists=file_exists,
                          file_size=file_size)


@app.route('/admin/approve/<int:user_id>', methods=['POST'])
@admin_required
def approve_user(user_id):
    """Approve a user."""
    db = get_db()
    db.execute('UPDATE users SET approved = 1 WHERE id = ?', (user_id,))
    db.commit()
    db.close()
    flash('User approved!', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/revoke/<int:user_id>', methods=['POST'])
@admin_required
def revoke_user(user_id):
    """Revoke user access."""
    db = get_db()
    db.execute('UPDATE users SET approved = 0 WHERE id = ?', (user_id,))
    db.commit()
    db.close()
    flash('User access revoked.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    """Delete a user."""
    db = get_db()
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    db.close()
    flash('User deleted.', 'success')
    return redirect(url_for('admin_dashboard'))


# ============================================
# MAIN
# ============================================

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)