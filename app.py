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
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import threading
import time

# Rate limiting
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    RATE_LIMIT_AVAILABLE = True
except ImportError:
    RATE_LIMIT_AVAILABLE = False

# Discord bot
try:
    import discord
    from discord.ext import commands, tasks
    DISCORD_AVAILABLE = True
except ImportError:
    DISCORD_AVAILABLE = False
    print("discord.py not installed - bot disabled")

# Load .env if exists
env_path = Path(__file__).parent / '.env'
if env_path.exists():
    print(f"Loading .env from {env_path}")
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                os.environ[key.strip()] = value.strip()
else:
    print(f"No .env file found at {env_path}")

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'change-this-in-production')

# Rate limiting setup
if RATE_LIMIT_AVAILABLE:
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://"
    )
else:
    limiter = None


def rate_limit(limit_string):
    """Rate limit decorator that works even if flask-limiter not installed."""
    def decorator(f):
        if limiter:
            return limiter.limit(limit_string)(f)
        return f
    return decorator

# Config
DATABASE = Path(__file__).parent / 'users.db'
DOWNLOADS_DIR = Path(__file__).parent / 'downloads'
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@zon-productions.com')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'changeme')
ADMIN_URL = os.environ.get('ADMIN_URL', 'zp-control-8x7k')  # Secret admin path

# Email config
SMTP_EMAIL = os.environ.get('SMTP_EMAIL', '')  # your-gmail@gmail.com
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')  # Gmail App Password
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SITE_URL = os.environ.get('SITE_URL', 'https://zon-productions.com')

# Discord bot config
DISCORD_BOT_TOKEN = os.environ.get('DISCORD_BOT_TOKEN', '')

# Game info
GAME_NAME = "NightShadow"
COMPANY_NAME = "Zon Productions"
GAME_FILE = os.environ.get('GAME_FILE', 'NightShadow.zip')

# Track file modification time
last_file_mtime = None


# ============================================
# EMAIL
# ============================================

def send_email(to_email, subject, html_body):
    """Send an email via SMTP."""
    if not SMTP_EMAIL or not SMTP_PASSWORD:
        print(f"Email not configured. Would send to {to_email}: {subject}")
        return False
    
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"{COMPANY_NAME} <{SMTP_EMAIL}>"
        msg['To'] = to_email
        
        msg.attach(MIMEText(html_body, 'html'))
        
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.sendmail(SMTP_EMAIL, to_email, msg.as_string())
        
        print(f"Email sent to {to_email}: {subject}")
        return True
    except Exception as e:
        print(f"Email failed: {e}")
        return False


def send_welcome_email(email, username):
    """Send welcome email after registration."""
    subject = f"Welcome to {GAME_NAME} - Registration Received"
    html = f"""
    <div style="font-family: monospace; background: #000; color: #00ff41; padding: 20px;">
        <h2 style="color: #00ff41;">> REGISTRATION_CONFIRMED</h2>
        <p>Hello {username},</p>
        <p>Your account has been created. You will receive another email once an admin approves your access.</p>
        <p style="color: #008f11;">// {COMPANY_NAME}</p>
    </div>
    """
    send_email(email, subject, html)


def send_approved_email(email, username):
    """Send email when user is approved."""
    subject = f"{GAME_NAME} - Access Granted!"
    html = f"""
    <div style="font-family: monospace; background: #000; color: #00ff41; padding: 20px;">
        <h2 style="color: #00ff41;">> ACCESS_GRANTED</h2>
        <p>Hello {username},</p>
        <p>Your account has been approved! You can now download {GAME_NAME}.</p>
        <p><a href="{SITE_URL}/login" style="color: #00ff41;">Click here to login and download</a></p>
        <p style="color: #008f11;">// {COMPANY_NAME}</p>
    </div>
    """
    send_email(email, subject, html)


def send_revoked_email(email, username):
    """Send email when user access is revoked."""
    subject = f"{GAME_NAME} - Access Revoked"
    html = f"""
    <div style="font-family: monospace; background: #000; color: #00ff41; padding: 20px;">
        <h2 style="color: #ff0040;">> ACCESS_REVOKED</h2>
        <p>Hello {username},</p>
        <p>Your download access has been revoked. If you believe this is an error, please contact the admin.</p>
        <p style="color: #008f11;">// {COMPANY_NAME}</p>
    </div>
    """
    send_email(email, subject, html)


def send_password_reset_email(email, username, token):
    """Send password reset email."""
    reset_link = f"{SITE_URL}/reset-password/{token}"
    subject = f"{GAME_NAME} - Password Reset"
    html = f"""
    <div style="font-family: monospace; background: #000; color: #00ff41; padding: 20px;">
        <h2 style="color: #00ff41;">> PASSWORD_RESET</h2>
        <p>Hello {username},</p>
        <p>Click the link below to reset your password. This link expires in 1 hour.</p>
        <p><a href="{reset_link}" style="color: #00ff41;">{reset_link}</a></p>
        <p>If you didn't request this, ignore this email.</p>
        <p style="color: #008f11;">// {COMPANY_NAME}</p>
    </div>
    """
    send_email(email, subject, html)


def send_admin_notification(user_email, username):
    """Notify admin of new registration."""
    subject = f"New Registration: {username}"
    html = f"""
    <div style="font-family: monospace; background: #000; color: #00ff41; padding: 20px;">
        <h2 style="color: #00ff41;">> NEW_REGISTRATION</h2>
        <p>A new user has registered:</p>
        <p>Username: {username}<br>Email: {user_email}</p>
        <p><a href="{SITE_URL}/admin" style="color: #00ff41;">Go to Admin Panel</a></p>
    </div>
    """
    send_email(ADMIN_EMAIL, subject, html)


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
    db.execute('''
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used INTEGER DEFAULT 0
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
        
        # Send emails
        send_welcome_email(email, username)
        send_admin_notification(email, username)
        
        flash('Registration successful! Please wait for admin approval.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html',
                          game_name=GAME_NAME,
                          company_name=COMPANY_NAME)


@app.route('/login', methods=['GET', 'POST'])
@rate_limit("5 per minute")
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
    return redirect(url_for('login'))


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
# PASSWORD RESET
# ============================================

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Request password reset."""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        if user:
            # Generate token
            token = secrets.token_urlsafe(32)
            expires_at = datetime.now() + timedelta(hours=1)
            
            # Delete old tokens for this email
            db.execute('DELETE FROM password_resets WHERE email = ?', (email,))
            
            # Save new token
            db.execute('INSERT INTO password_resets (email, token, expires_at) VALUES (?, ?, ?)',
                      (email, token, expires_at))
            db.commit()
            
            # Send email
            send_password_reset_email(email, user['username'], token)
        
        db.close()
        
        # Always show success (don't reveal if email exists)
        flash('If that email exists, a reset link has been sent.', 'success')
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html',
                          game_name=GAME_NAME,
                          company_name=COMPANY_NAME)


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Reset password with token."""
    db = get_db()
    reset = db.execute(
        'SELECT * FROM password_resets WHERE token = ? AND used = 0 AND expires_at > ?',
        (token, datetime.now())
    ).fetchone()
    
    if not reset:
        db.close()
        flash('Invalid or expired reset link.', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'error')
        elif password != confirm:
            flash('Passwords do not match.', 'error')
        else:
            # Update password
            password_hash = generate_password_hash(password)
            db.execute('UPDATE users SET password_hash = ? WHERE email = ?',
                      (password_hash, reset['email']))
            
            # Mark token as used
            db.execute('UPDATE password_resets SET used = 1 WHERE token = ?', (token,))
            db.commit()
            db.close()
            
            flash('Password updated! You can now login.', 'success')
            return redirect(url_for('login'))
    
    db.close()
    return render_template('reset_password.html',
                          token=token,
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

@app.route(f'/<path:admin_path>/login', methods=['GET', 'POST'])
def admin_login(admin_path):
    """Admin login."""
    if admin_path != ADMIN_URL:
        abort(404)
    
    if request.method == 'POST':
        # Rate limit check (5 attempts per minute)
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        if email == ADMIN_EMAIL.lower() and password == ADMIN_PASSWORD:
            session['is_admin'] = True
            session['admin_email'] = email
            return redirect(url_for('admin_dashboard', admin_path=ADMIN_URL))
        
        flash('Invalid admin credentials', 'error')
    
    return render_template('admin_login.html',
                          game_name=GAME_NAME,
                          company_name=COMPANY_NAME,
                          admin_url=ADMIN_URL)


@app.route(f'/<path:admin_path>/logout')
def admin_logout(admin_path):
    """Admin logout."""
    if admin_path != ADMIN_URL:
        abort(404)
    session.pop('is_admin', None)
    session.pop('admin_email', None)
    flash('Admin logged out.', 'success')
    return redirect(url_for('login'))


def admin_required(f):
    """Require admin login."""
    @wraps(f)
    def decorated(admin_path, *args, **kwargs):
        if admin_path != ADMIN_URL:
            abort(404)
        if not session.get('is_admin'):
            flash('Admin access required.', 'error')
            return redirect(url_for('admin_login', admin_path=ADMIN_URL))
        return f(admin_path, *args, **kwargs)
    return decorated


@app.route(f'/<path:admin_path>')
@admin_required
def admin_dashboard(admin_path):
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
                          file_size=file_size,
                          admin_url=ADMIN_URL)


@app.route(f'/<path:admin_path>/approve/<int:user_id>', methods=['POST'])
@admin_required
def approve_user(admin_path, user_id):
    """Approve a user."""
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if user:
        db.execute('UPDATE users SET approved = 1 WHERE id = ?', (user_id,))
        db.commit()
        send_approved_email(user['email'], user['username'])
    db.close()
    flash('User approved!', 'success')
    return redirect(url_for('admin_dashboard', admin_path=ADMIN_URL))


@app.route(f'/<path:admin_path>/revoke/<int:user_id>', methods=['POST'])
@admin_required
def revoke_user(admin_path, user_id):
    """Revoke user access."""
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if user:
        db.execute('UPDATE users SET approved = 0 WHERE id = ?', (user_id,))
        db.commit()
        send_revoked_email(user['email'], user['username'])
    db.close()
    flash('User access revoked.', 'success')
    return redirect(url_for('admin_dashboard', admin_path=ADMIN_URL))


@app.route(f'/<path:admin_path>/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(admin_path, user_id):
    """Delete a user."""
    db = get_db()
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    db.close()
    flash('User deleted.', 'success')
    return redirect(url_for('admin_dashboard', admin_path=ADMIN_URL))


# ============================================
# API ENDPOINTS (for launcher)
# ============================================

@app.route('/api/login', methods=['POST'])
@rate_limit("10 per minute")
def api_login():
    """API login for launcher."""
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    
    if not email or not password:
        return {'success': False, 'error': 'Email and password required'}, 400
    
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    db.close()
    
    if user and check_password_hash(user['password_hash'], password):
        if user['approved']:
            # Generate a simple token (in production, use proper JWT)
            token = secrets.token_urlsafe(32)
            return {
                'success': True,
                'token': token,
                'username': user['username'],
                'approved': True
            }
        else:
            return {
                'success': True,
                'approved': False,
                'error': 'Account pending approval'
            }
    
    return {'success': False, 'error': 'Invalid credentials'}, 401


@app.route('/api/game-info', methods=['GET'])
def api_game_info():
    """Get game file info for launcher."""
    game_path = DOWNLOADS_DIR / GAME_FILE
    
    if game_path.exists():
        size_bytes = game_path.stat().st_size
        mtime = game_path.stat().st_mtime
        return {
            'available': True,
            'filename': GAME_FILE,
            'size_bytes': size_bytes,
            'size_formatted': f"{size_bytes / (1024**3):.2f} GB" if size_bytes > 1024**3 else f"{size_bytes / (1024**2):.0f} MB",
            'last_updated': datetime.fromtimestamp(mtime).isoformat()
        }
    
    return {'available': False}


@app.route('/api/download', methods=['POST'])
@rate_limit("5 per hour")
def api_download():
    """API download for launcher - re-authenticates."""
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    
    if not email or not password:
        return {'success': False, 'error': 'Credentials required'}, 400
    
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    db.close()
    
    if not user or not check_password_hash(user['password_hash'], password):
        return {'success': False, 'error': 'Invalid credentials'}, 401
    
    if not user['approved']:
        return {'success': False, 'error': 'Account not approved'}, 403
    
    # Serve the file
    game_path = DOWNLOADS_DIR / GAME_FILE
    if not game_path.exists():
        return {'success': False, 'error': 'Game file not available'}, 404
    
    return send_from_directory(DOWNLOADS_DIR, GAME_FILE, as_attachment=True)


# ============================================
# DISCORD BOT
# ============================================

discord_bot = None
discord_bot_started = False
DISCORD_CHANNELS_FILE = Path(__file__).parent / 'discord_channels.json'


def load_discord_channels():
    """Load configured channels from file."""
    if DISCORD_CHANNELS_FILE.exists():
        try:
            import json
            with open(DISCORD_CHANNELS_FILE) as f:
                return json.load(f)
        except:
            return {}
    return {}


def save_discord_channels(channels):
    """Save configured channels to file."""
    import json
    with open(DISCORD_CHANNELS_FILE, 'w') as f:
        json.dump(channels, f, indent=2)


def get_file_mtime():
    """Get modification time of game file."""
    game_path = DOWNLOADS_DIR / GAME_FILE
    if game_path.exists():
        return game_path.stat().st_mtime
    return None


def get_file_size_str():
    """Get human-readable file size."""
    game_path = DOWNLOADS_DIR / GAME_FILE
    if game_path.exists():
        size_bytes = game_path.stat().st_size
        if size_bytes > 1024**3:
            return f"{size_bytes / (1024**3):.2f} GB"
        else:
            return f"{size_bytes / (1024**2):.0f} MB"
    return "N/A"


def setup_discord_bot():
    """Set up and run Discord bot."""
    global discord_bot, last_file_mtime, discord_bot_started
    
    if discord_bot_started:
        print("Discord bot already started, skipping...")
        return
    
    # Re-read config in case it wasn't available at import time
    bot_token = os.environ.get('DISCORD_BOT_TOKEN', '')
    
    print(f"Discord setup - Token present: {bool(bot_token)}")
    
    if not DISCORD_AVAILABLE:
        print("Discord bot disabled - discord.py not installed")
        return
    
    if not bot_token:
        print("Discord bot disabled - no DISCORD_BOT_TOKEN in .env")
        return
    
    discord_bot_started = True
    
    # Initialize last known mtime
    last_file_mtime = get_file_mtime()
    
    intents = discord.Intents.default()
    intents.message_content = True
    
    bot = commands.Bot(command_prefix='%', intents=intents)
    discord_bot = bot
    
    @bot.event
    async def on_ready():
        print(f"Discord bot connected as {bot.user}")
        print(f"Bot is in {len(bot.guilds)} server(s)")
        check_for_updates.start()
        
        channels = load_discord_channels()
        print(f"Update notifications configured for {len(channels)} server(s)")
    
    @tasks.loop(minutes=5)
    async def check_for_updates():
        """Check if game file has been updated."""
        global last_file_mtime
        
        current_mtime = get_file_mtime()
        
        if current_mtime is None:
            return
        
        if last_file_mtime is not None and current_mtime > last_file_mtime:
            # File has been updated - notify all configured channels
            channels = load_discord_channels()
            
            if not channels:
                print("No channels configured for updates")
                last_file_mtime = current_mtime
                return
            
            file_size = get_file_size_str()
            update_time = datetime.fromtimestamp(current_mtime).strftime('%Y-%m-%d %H:%M')
            
            embed = discord.Embed(
                title="🎮 NEW UPDATE AVAILABLE",
                description=f"**{GAME_NAME}** has been updated!",
                color=0x00ff41
            )
            embed.add_field(name="File", value=GAME_FILE, inline=True)
            embed.add_field(name="Size", value=file_size, inline=True)
            embed.add_field(name="Updated", value=update_time, inline=True)
            embed.add_field(
                name="Download",
                value=f"[Click here to download]({SITE_URL}/download)",
                inline=False
            )
            embed.set_footer(text=f"{COMPANY_NAME} // {GAME_NAME} Protocol")
            
            for guild_id, ch_id in channels.items():
                try:
                    ch = bot.get_channel(int(ch_id))
                    if ch:
                        await ch.send(embed=embed)
                        print(f"Sent update notification to channel {ch_id} in guild {guild_id}")
                    else:
                        print(f"Could not find channel {ch_id}")
                except Exception as e:
                    print(f"Failed to send to channel {ch_id}: {e}")
        
        last_file_mtime = current_mtime
        
        last_file_mtime = current_mtime
    
    @bot.command(name='NS', aliases=['ns', 'nightshadow'])
    async def nightshadow_info(ctx):
        """Show game info and download status."""
        game_path = DOWNLOADS_DIR / GAME_FILE
        
        if game_path.exists():
            file_size = get_file_size_str()
            mtime = datetime.fromtimestamp(game_path.stat().st_mtime).strftime('%Y-%m-%d %H:%M')
            status = "🟢 ONLINE"
        else:
            file_size = "N/A"
            mtime = "N/A"
            status = "🔴 OFFLINE"
        
        embed = discord.Embed(
            title=f">> {GAME_NAME.upper()} PROTOCOL",
            description="// ASYMMETRICAL MULTIPLAYER STEALTH COMBAT",
            color=0x00ff41
        )
        embed.add_field(name="Status", value=status, inline=True)
        embed.add_field(name="File Size", value=file_size, inline=True)
        embed.add_field(name="Last Updated", value=mtime, inline=True)
        embed.add_field(
            name="Download Portal",
            value=f"[{SITE_URL}]({SITE_URL})",
            inline=False
        )
        embed.set_footer(text=f"{COMPANY_NAME}")
        
        await ctx.send(embed=embed)
    
    @bot.command(name='status')
    async def server_status(ctx):
        """Show download server status."""
        game_path = DOWNLOADS_DIR / GAME_FILE
        
        embed = discord.Embed(
            title=">> SYSTEM_STATUS",
            color=0x00ff41
        )
        
        if game_path.exists():
            embed.add_field(name="Download Server", value="🟢 ONLINE", inline=False)
            embed.add_field(name="File", value=GAME_FILE, inline=True)
            embed.add_field(name="Size", value=get_file_size_str(), inline=True)
        else:
            embed.add_field(name="Download Server", value="🔴 OFFLINE", inline=False)
            embed.add_field(name="File", value="Not available", inline=True)
        
        embed.set_footer(text=f"{COMPANY_NAME}")
        await ctx.send(embed=embed)
    
    @bot.command(name='setchannel')
    @commands.has_permissions(administrator=True)
    async def set_update_channel(ctx):
        """Set this channel to receive game updates. Admin only."""
        channels = load_discord_channels()
        guild_id = str(ctx.guild.id)
        channel_id = ctx.channel.id
        
        channels[guild_id] = channel_id
        save_discord_channels(channels)
        
        embed = discord.Embed(
            title="✅ UPDATE CHANNEL SET",
            description=f"This channel will now receive **{GAME_NAME}** update notifications.",
            color=0x00ff41
        )
        embed.add_field(name="Channel", value=f"<#{channel_id}>", inline=True)
        embed.add_field(name="Server", value=ctx.guild.name, inline=True)
        embed.set_footer(text="Use %removechannel to disable notifications")
        
        await ctx.send(embed=embed)
        print(f"Update channel set: guild={guild_id}, channel={channel_id}")
    
    @set_update_channel.error
    async def set_channel_error(ctx, error):
        if isinstance(error, commands.MissingPermissions):
            await ctx.send("❌ You need **Administrator** permission to use this command.")
    
    @bot.command(name='removechannel')
    @commands.has_permissions(administrator=True)
    async def remove_update_channel(ctx):
        """Remove this server from update notifications. Admin only."""
        channels = load_discord_channels()
        guild_id = str(ctx.guild.id)
        
        if guild_id in channels:
            del channels[guild_id]
            save_discord_channels(channels)
            
            embed = discord.Embed(
                title="🔕 UPDATES DISABLED",
                description=f"This server will no longer receive **{GAME_NAME}** update notifications.",
                color=0xff0040
            )
            await ctx.send(embed=embed)
            print(f"Update channel removed: guild={guild_id}")
        else:
            await ctx.send("This server doesn't have update notifications enabled.")
    
    @remove_update_channel.error
    async def remove_channel_error(ctx, error):
        if isinstance(error, commands.MissingPermissions):
            await ctx.send("❌ You need **Administrator** permission to use this command.")
    
    # Run bot in background thread
    def run_bot():
        try:
            print(f"Starting Discord bot...")
            bot.run(bot_token)
        except Exception as e:
            print(f"Discord bot error: {e}")
    
    thread = threading.Thread(target=run_bot, daemon=True)
    thread.start()
    print("Discord bot thread started")


# ============================================
# MAIN
# ============================================

# Start Discord bot (runs once, even with multiple gunicorn workers)
setup_discord_bot()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)