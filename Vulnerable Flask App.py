# secure_app.py
"""
Secure Flask Authentication Application
Addresses multiple security vulnerabilities and implements best practices
"""

import os
import sqlite3
import hashlib
import secrets
import time
import re
from datetime import datetime, timedelta
from functools import wraps
from contextlib import contextmanager

from flask import Flask, request, render_template_string, session, redirect, url_for, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import jwt
from email_validator import validate_email, EmailNotValidError

# Initialize Flask app with security configurations
app = Flask(__name__)

# Security Configuration
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', secrets.token_hex(32)),
    SESSION_COOKIE_SECURE=True,  # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,  # Prevent XSS
    SESSION_COOKIE_SAMESITE='Lax',  # CSRF protection
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    WTF_CSRF_ENABLED=True,
    DATABASE_PATH=os.environ.get('DATABASE_PATH', 'secure_users.db'),
    MAX_LOGIN_ATTEMPTS=5,
    LOCKOUT_DURATION=900,  # 15 minutes in seconds
    JWT_SECRET_KEY=os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32)),
    JWT_ALGORITHM='HS256'
)

# Rate limiting setup
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Security headers middleware
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    return response

class DatabaseManager:
    """Secure database operations with connection pooling and prepared statements"""
    
    def __init__(self, db_path):
        self.db_path = db_path
        self.init_database()
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            conn.row_factory = sqlite3.Row  # Enable column access by name
            # Enable foreign keys and WAL mode for better concurrency
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            yield conn
        except sqlite3.Error as e:
            if conn:
                conn.rollback()
            app.logger.error(f"Database error: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    def init_database(self):
        """Initialize database with secure schema"""
        with self.get_connection() as conn:
            # Users table with enhanced security fields
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE,
                    failed_login_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMP,
                    password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    two_factor_secret TEXT,
                    email_verified BOOLEAN DEFAULT FALSE
                )
            ''')
            
            # Login attempts tracking table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    username TEXT,
                    success BOOLEAN NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    user_agent TEXT,
                    additional_info TEXT
                )
            ''')
            
            # Session management table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS user_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    session_token TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    is_active BOOLEAN DEFAULT TRUE,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # Audit log table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT NOT NULL,
                    details TEXT,
                    ip_address TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            conn.commit()

class UserManager:
    """Secure user management with proper authentication and authorization"""
    
    def __init__(self, db_manager):
        self.db = db_manager
    
    def validate_password_strength(self, password):
        """Validate password meets security requirements"""
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
    
    def validate_username(self, username):
        """Validate username format and availability"""
        if not username or len(username) < 3:
            return False, "Username must be at least 3 characters long"
        
        if len(username) > 30:
            return False, "Username must be no more than 30 characters long"
        
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            return False, "Username can only contain letters, numbers, underscores, and hyphens"
        
        return True, "Username is valid"
    
    def create_user(self, username, email, password):
        """Create a new user with secure password hashing"""
        try:
            # Validate input
            username_valid, username_msg = self.validate_username(username)
            if not username_valid:
                return False, username_msg
            
            password_valid, password_msg = self.validate_password_strength(password)
            if not password_valid:
                return False, password_msg
            
            # Validate email
            try:
                validate_email(email)
            except EmailNotValidError:
                return False, "Invalid email address"
            
            # Generate salt and hash password
            salt = secrets.token_hex(32)
            password_hash = generate_password_hash(password + salt)
            
            with self.db.get_connection() as conn:
                # Check if user already exists
                existing = conn.execute(
                    "SELECT id FROM users WHERE username = ? OR email = ?",
                    (username, email)
                ).fetchone()
                
                if existing:
                    return False, "Username or email already exists"
                
                # Insert new user
                conn.execute('''
                    INSERT INTO users (username, email, password_hash, salt)
                    VALUES (?, ?, ?, ?)
                ''', (username, email, password_hash, salt))
                
                conn.commit()
                
                # Log user creation
                self.log_audit_event(None, "USER_CREATED", f"Username: {username}, Email: {email}")
                
                return True, "User created successfully"
                
        except Exception as e:
            app.logger.error(f"Error creating user: {e}")
            return False, "An error occurred while creating the user"
    
    def authenticate_user(self, username, password, ip_address, user_agent):
        """Authenticate user with rate limiting and lockout protection"""
        try:
            with self.db.get_connection() as conn:
                # Check if IP is temporarily blocked
                if self.is_ip_blocked(ip_address):
                    self.log_login_attempt(ip_address, username, False, user_agent, "IP blocked")
                    return False, "Too many failed attempts. Please try again later."
                
                # Get user information
                user = conn.execute('''
                    SELECT id, username, email, password_hash, salt, failed_login_attempts, 
                           locked_until, is_active, last_login
                    FROM users 
                    WHERE username = ? OR email = ?
                ''', (username, username)).fetchone()
                
                if not user:
                    self.log_login_attempt(ip_address, username, False, user_agent, "User not found")
                    return False, "Invalid credentials"
                
                # Check if account is locked
                if user['locked_until'] and datetime.fromisoformat(user['locked_until']) > datetime.now():
                    self.log_login_attempt(ip_address, username, False, user_agent, "Account locked")
                    return False, "Account is temporarily locked. Please try again later."
                
                # Check if account is active
                if not user['is_active']:
                    self.log_login_attempt(ip_address, username, False, user_agent, "Account inactive")
                    return False, "Account is disabled"
                
                # Verify password
                if check_password_hash(user['password_hash'], password + user['salt']):
                    # Successful login - reset failed attempts and update last login
                    conn.execute('''
                        UPDATE users 
                        SET failed_login_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP
                        WHERE id = ?
                    ''', (user['id'],))
                    
                    conn.commit()
                    
                    self.log_login_attempt(ip_address, username, True, user_agent, "Successful login")
                    self.log_audit_event(user['id'], "LOGIN_SUCCESS", f"IP: {ip_address}")
                    
                    return True, dict(user)
                else:
                    # Failed login - increment failed attempts
                    failed_attempts = user['failed_login_attempts'] + 1
                    locked_until = None
                    
                    if failed_attempts >= app.config['MAX_LOGIN_ATTEMPTS']:
                        locked_until = datetime.now() + timedelta(seconds=app.config['LOCKOUT_DURATION'])
                    
                    conn.execute('''
                        UPDATE users 
                        SET failed_login_attempts = ?, locked_until = ?
                        WHERE id = ?
                    ''', (failed_attempts, locked_until, user['id']))
                    
                    conn.commit()
                    
                    self.log_login_attempt(ip_address, username, False, user_agent, "Invalid password")
                    self.log_audit_event(user['id'], "LOGIN_FAILED", f"IP: {ip_address}, Attempts: {failed_attempts}")
                    
                    return False, "Invalid credentials"
                    
        except Exception as e:
            app.logger.error(f"Authentication error: {e}")
            return False, "An error occurred during authentication"
    
    def is_ip_blocked(self, ip_address):
        """Check if IP address is temporarily blocked due to failed attempts"""
        try:
            with self.db.get_connection() as conn:
                # Count failed attempts from this IP in the last hour
                one_hour_ago = datetime.now() - timedelta(hours=1)
                failed_count = conn.execute('''
                    SELECT COUNT(*) 
                    FROM login_attempts 
                    WHERE ip_address = ? AND success = FALSE AND timestamp > ?
                ''', (ip_address, one_hour_ago)).fetchone()[0]
                
                return failed_count >= app.config['MAX_LOGIN_ATTEMPTS'] * 2
        except Exception as e:
            app.logger.error(f"Error checking IP block status: {e}")
            return False
    
    def log_login_attempt(self, ip_address, username, success, user_agent, additional_info):
        """Log login attempts for security monitoring"""
        try:
            with self.db.get_connection() as conn:
                conn.execute('''
                    INSERT INTO login_attempts (ip_address, username, success, user_agent, additional_info)
                    VALUES (?, ?, ?, ?, ?)
                ''', (ip_address, username, success, user_agent, additional_info))
                conn.commit()
        except Exception as e:
            app.logger.error(f"Error logging login attempt: {e}")
    
    def log_audit_event(self, user_id, action, details):
        """Log audit events for compliance and security monitoring"""
        try:
            with self.db.get_connection() as conn:
                conn.execute('''
                    INSERT INTO audit_log (user_id, action, details, ip_address)
                    VALUES (?, ?, ?, ?)
                ''', (user_id, action, details, request.remote_addr if request else None))
                conn.commit()
        except Exception as e:
            app.logger.error(f"Error logging audit event: {e}")

class SessionManager:
    """Secure session management with JWT tokens"""
    
    def __init__(self, db_manager):
        self.db = db_manager
    
    def create_session(self, user_id, ip_address, user_agent):
        """Create a secure session token"""
        try:
            session_token = secrets.token_urlsafe(32)
            expires_at = datetime.now() + app.config['PERMANENT_SESSION_LIFETIME']
            
            # Create JWT payload
            jwt_payload = {
                'user_id': user_id,
                'session_token': session_token,
                'exp': expires_at.timestamp(),
                'iat': datetime.now().timestamp(),
                'ip': ip_address
            }
            
            # Generate JWT token
            jwt_token = jwt.encode(
                jwt_payload,
                app.config['JWT_SECRET_KEY