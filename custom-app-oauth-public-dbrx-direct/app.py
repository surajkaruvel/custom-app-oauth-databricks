#!/usr/bin/env python3
"""
Databricks Direct OAuth App - Public Client
Authenticates directly with Databricks OAuth endpoints using PKCE (no client secret)
"""

import os
import logging
import requests
import secrets
import hashlib
import base64
from datetime import datetime, timedelta
from urllib.parse import urlencode, parse_qs
from flask import Flask, render_template, request, jsonify, redirect, url_for, session

# Load environment variables from config.env if it exists
def load_config_env():
    """Load environment variables from config.env file if it exists"""
    config_file = os.path.join(os.path.dirname(__file__), 'config.env')
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    # Remove quotes if present
                    value = value.strip('"\'')
                    os.environ[key] = value
        print(f"✅ Loaded configuration from {config_file}")
    else:
        print(f"⚠️  No config.env file found at {config_file}")

# Load config.env before anything else
load_config_env()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Flask app configuration
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'databricks-public-oauth-app-secret')

# Security: Configure secure session settings
app.config.update(
    SESSION_COOKIE_SECURE=False,  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8)
)

# Configuration
class Config:
    def __init__(self):
        # Databricks OAuth Configuration
        self.databricks_server_hostname = os.environ.get('DATABRICKS_SERVER_HOSTNAME', '')
        self.client_id = os.environ.get('CLIENT_ID', '')
        # Note: No client_secret for public client
        self.redirect_uri = os.environ.get('REDIRECT_URI', 'http://localhost:8003/callback')
        self.scope = os.environ.get('OAUTH_SCOPE', 'all-apis offline_access')
        
        # Databricks SQL Endpoint Configuration
        self.databricks_http_path = os.environ.get('DATABRICKS_HTTP_PATH', '')
        
        # Validate required configuration
        if not self.databricks_server_hostname:
            logger.warning("Databricks server hostname not configured")
        
        if not self.client_id:
            logger.warning("Databricks client ID not configured")
        
        if not self.databricks_http_path:
            logger.warning("Databricks SQL endpoint not fully configured")

config = Config()

def generate_pkce_pair():
    """Generate PKCE code verifier and challenge"""
    # Generate code verifier (43-128 characters)
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    
    # Generate code challenge (SHA256 hash of verifier)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('utf-8')).digest()
    ).decode('utf-8').rstrip('=')
    
    return code_verifier, code_challenge

def exchange_code_for_token(authorization_code, code_verifier):
    """Exchange authorization code for tokens using PKCE only (Public Client)"""
    token_data = {
        'grant_type': 'authorization_code',
        'client_id': config.client_id,
        # Note: No client_secret for public client
        'code': authorization_code,
        'redirect_uri': config.redirect_uri,
        'code_verifier': code_verifier
    }
    
    try:
        token_url = f"https://{config.databricks_server_hostname}/oidc/v1/token"
        response = requests.post(
            token_url,
            data=token_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Token exchange failed: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_details = e.response.json()
                logger.error(f"Error details: {error_details}")
            except:
                logger.error(f"HTTP {e.response.status_code}: {e.response.text}")
        raise Exception(f"Failed to exchange authorization code: {str(e)}")

def refresh_access_token():
    """Use refresh token to get new access token from Databricks (Public Client)"""
    refresh_token = session.get('refresh_token')
    if not refresh_token:
        logger.error("No refresh token available")
        return False
    
    refresh_data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': config.client_id
        # Note: No client_secret for public client
    }
    
    try:
        logger.info("Refreshing access token using refresh token (public client)")
        token_url = f"https://{config.databricks_server_hostname}/oidc/v1/token"
        response = requests.post(
            token_url,
            data=refresh_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=30
        )
        response.raise_for_status()
        token_response = response.json()
        
        # Update session with new tokens
        session['access_token'] = token_response.get('access_token')
        if token_response.get('refresh_token'):  # New refresh token might be provided
            session['refresh_token'] = token_response.get('refresh_token')
        session['token_obtained'] = datetime.now().isoformat()
        
        logger.info("Access token refreshed successfully")
        return True
        
    except requests.RequestException as e:
        logger.error(f"Token refresh failed: {str(e)}")
        # Check if it's a refresh token expiration (401 or 400 with invalid_grant)
        if hasattr(e, 'response') and e.response is not None:
            if e.response.status_code in [400, 401]:
                try:
                    error_data = e.response.json()
                    if error_data.get('error') == 'invalid_grant':
                        logger.error("Refresh token has expired or is invalid")
                        # Clear the invalid refresh token
                        session.pop('refresh_token', None)
                except:
                    pass
        return False

def is_token_expired():
    """Check if tokens are expired or will expire soon (5 minute buffer)"""
    token_obtained_str = session.get('token_obtained')
    if not token_obtained_str:
        return True
    
    try:
        token_obtained = datetime.fromisoformat(token_obtained_str)
        # Check if token is older than 55 minutes (5 minute buffer before 1 hour expiration)
        time_elapsed = datetime.now() - token_obtained
        return time_elapsed > timedelta(minutes=55)
    except Exception:
        return True

def refresh_tokens_if_needed():
    """Check and refresh tokens if they're expired or will expire soon"""
    if not is_token_expired():
        return True  # Tokens are still valid
    
    logger.info("Tokens are expired or will expire soon, attempting refresh")
    
    # Refresh the Databricks access token
    if not refresh_access_token():
        logger.error("Failed to refresh access token")
        return False
    
    logger.info("Tokens refreshed successfully")
    return True

def execute_sql_query(query, warehouse_id):
    """Execute SQL query on Databricks SQL endpoint"""
    try:
        # Get access token from session
        access_token = session.get('access_token')
        if not access_token:
            raise Exception("No access token available")
        
        workspace_url = f"https://{config.databricks_server_hostname}"
        
        # Create SQL execution request
        sql_data = {
            'warehouse_id': warehouse_id,
            'statement': query,
            'wait_timeout': '30s'
        }
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        
        response = requests.post(
            f"{workspace_url}/api/2.0/sql/statements",
            json=sql_data,
            headers=headers,
            timeout=60
        )
        response.raise_for_status()
        result = response.json()
        
        logger.info(f"SQL query executed successfully on warehouse {warehouse_id}: {result.get('statement_id')}")
        return result
        
    except Exception as e:
        logger.error(f"SQL query execution failed on warehouse {warehouse_id}: {str(e)}")
        raise

# Middleware to check and refresh tokens before protected routes
@app.before_request
def check_token_validity():
    """Check token validity before each request to protected endpoints"""
    # Only check tokens for protected endpoints
    protected_endpoints = ['sql_interface', 'execute_sql']
    
    if request.endpoint in protected_endpoints:
        # Check if user has tokens
        if 'access_token' not in session:
            logger.info("No tokens found, redirecting to login")
            return redirect(url_for('index'))
        
        # Check if tokens need refresh
        if not refresh_tokens_if_needed():
            logger.error("Token refresh failed, clearing session and redirecting to login")
            session.clear()
            return redirect(url_for('index'))

@app.route('/')
def index():
    """Main page - login or SQL interface"""
    try:
        logger.info("Serving index page")
        
        # Check if user is authenticated
        if 'access_token' in session:
            # User is authenticated, redirect to SQL interface
            return redirect(url_for('sql_interface'))
        
        # User not authenticated, show login page
        return render_template('index.html',
                             client_id=config.client_id,
                             server_hostname=config.databricks_server_hostname)
    except Exception as e:
        logger.error(f"Error serving index page: {str(e)}")
        return f"Error: {str(e)}", 500

@app.route('/login')
def login():
    """Initiate OAuth login with PKCE"""
    try:
        # Generate PKCE parameters
        code_verifier, code_challenge = generate_pkce_pair()
        state = secrets.token_urlsafe(32)
        
        # Store PKCE parameters in session
        session['code_verifier'] = code_verifier
        session['oauth_state'] = state
        
        # Build authorization URL
        auth_params = {
            'client_id': config.client_id,
            'response_type': 'code',
            'scope': config.scope,
            'redirect_uri': config.redirect_uri,
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }
        
        auth_url = f"https://{config.databricks_server_hostname}/oidc/v1/authorize?" + urlencode(auth_params)
        
        logger.info("Redirecting to Databricks OAuth authorization (public client)")
        return redirect(auth_url)
        
    except Exception as e:
        logger.error(f"Error initiating login: {str(e)}")
        return f"Login error: {str(e)}", 500

@app.route('/callback')
def callback():
    """Handle OAuth callback"""
    try:
        # Get authorization code and state
        authorization_code = request.args.get('code')
        returned_state = request.args.get('state')
        error = request.args.get('error')
        
        if error:
            logger.error(f"OAuth error: {error}")
            return f"OAuth error: {error}", 400
        
        if not authorization_code:
            logger.error("No authorization code received")
            return "No authorization code received", 400
        
        # Verify state parameter
        if returned_state != session.get('oauth_state'):
            logger.error("Invalid state parameter")
            return "Invalid state parameter", 400
        
        # Exchange code for tokens
        code_verifier = session.get('code_verifier')
        if not code_verifier:
            logger.error("No code verifier in session")
            return "Invalid session state", 400
        
        logger.info("Exchanging authorization code for tokens (public client)")
        token_response = exchange_code_for_token(authorization_code, code_verifier)
        
        # Store tokens in session
        session['access_token'] = token_response.get('access_token')
        session['refresh_token'] = token_response.get('refresh_token')
        session['token_obtained'] = datetime.now().isoformat()
        
        # Clean up session
        session.pop('code_verifier', None)
        session.pop('oauth_state', None)
        
        logger.info("Databricks OAuth flow completed successfully (public client)")
        return redirect(url_for('sql_interface'))
        
    except Exception as e:
        logger.error(f"Error processing OAuth callback: {str(e)}")
        return f"Callback error: {str(e)}", 500

@app.route('/sql')
def sql_interface():
    """SQL query interface"""
    if 'access_token' not in session:
        return redirect(url_for('index'))
    
    workspace_url = f"https://{config.databricks_server_hostname}"
    token_obtained = session.get('token_obtained')
    
    # Extract default warehouse ID from config if available
    default_warehouse_id = ''
    if config.databricks_http_path and '/warehouses/' in config.databricks_http_path:
        default_warehouse_id = config.databricks_http_path.split('/warehouses/')[-1]
    
    return render_template('sql_interface.html',
                         workspace_url=workspace_url,
                         token_obtained=token_obtained,
                         default_warehouse_id=default_warehouse_id,
                         server_hostname=config.databricks_server_hostname)

@app.route('/execute-sql', methods=['POST'])
def execute_sql():
    """Execute SQL query"""
    try:
        if 'access_token' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        query = request.json.get('query')
        warehouse_id = request.json.get('warehouse_id')
        
        if not query:
            return jsonify({'error': 'Missing query'}), 400
        
        if not warehouse_id:
            return jsonify({'error': 'Missing warehouse ID'}), 400
        
        # Execute the SQL query with the specified warehouse
        result = execute_sql_query(query, warehouse_id)
        
        return jsonify({
            'success': True,
            'result': result,
            'executed_at': datetime.now().isoformat(),
            'warehouse_id': warehouse_id
        })
        
    except Exception as e:
        logger.error(f"SQL execution error: {str(e)}")
        return jsonify({
            'success': False,
            'error': f"SQL execution failed: {str(e)}"
        }), 500

@app.route('/logout')
def logout():
    """Clear session and logout"""
    session.clear()
    return redirect(url_for('index'))

@app.route('/health')
def health():
    """Health check endpoint"""
    authenticated = 'access_token' in session
    
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'authenticated': authenticated,
        'databricks_configured': bool(config.databricks_server_hostname and config.client_id),
        'sql_endpoint_configured': bool(config.databricks_http_path),
        'client_type': 'public'
    })

@app.route('/token-status')
def token_status():
    """Get current token status and expiration info"""
    if 'access_token' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    token_obtained_str = session.get('token_obtained')
    if not token_obtained_str:
        return jsonify({'error': 'No token timestamp found'}), 400
    
    try:
        token_obtained = datetime.fromisoformat(token_obtained_str)
        time_elapsed = datetime.now() - token_obtained
        time_remaining = timedelta(hours=1) - time_elapsed
        
        return jsonify({
            'token_obtained': token_obtained_str,
            'time_elapsed_minutes': int(time_elapsed.total_seconds() / 60),
            'time_remaining_minutes': int(time_remaining.total_seconds() / 60),
            'expires_soon': is_token_expired(),
            'has_refresh_token': 'refresh_token' in session,
            'client_type': 'public'
        })
    except Exception as e:
        return jsonify({'error': f'Error calculating token status: {str(e)}'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8003))
    debug = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    
    logger.info(f"Starting Databricks Public OAuth App on port {port}")
    logger.info(f"Client ID: {config.client_id}")
    logger.info(f"Client Type: Public (PKCE only)")
    logger.info(f"Databricks Server: {config.databricks_server_hostname}")
    logger.info(f"Redirect URI: {config.redirect_uri}")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
