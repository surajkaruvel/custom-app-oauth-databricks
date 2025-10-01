#!/usr/bin/env python3
"""
Databricks SQL Interface - Web Application (Session-Independent Refresh Tokens)

This version uses Okta Web Application with Authorization Code Flow instead of SPA with PKCE.
Key difference: Refresh tokens are independent of Okta web sessions.

Features:
- Session-independent refresh tokens (survive Okta web logout)
- Automatic token refresh with 5-minute buffer
- Long-lived sessions (up to 90 days)
- Databricks SQL endpoint integration
- Dynamic warehouse ID input
"""

import os
import logging
import secrets
import base64
import hashlib
from datetime import datetime, timedelta
from urllib.parse import urlencode
import requests
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from openai import OpenAI
import openai

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
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'webapp-oauth-app-secret')

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
        # Okta Web Application Configuration (Authorization Code Flow)
        self.issuer_url = os.environ.get('ISSUER_URL', '')
        self.client_id = os.environ.get('CLIENT_ID', '')
        self.client_secret = os.environ.get('CLIENT_SECRET', '')  # Required for Web Apps
        self.redirect_uri = os.environ.get('REDIRECT_URI', 'http://localhost:6000/callback')
        self.oauth_scope = os.environ.get('OAUTH_SCOPE', 'openid profile email all-apis offline_access')
        
        # Databricks Configuration
        self.databricks_server_hostname = os.environ.get('DATABRICKS_SERVER_HOSTNAME', '')
        self.databricks_http_path = os.environ.get('DATABRICKS_HTTP_PATH', '')
        
        # Model Serving Configuration
        self.model_serving_endpoint = os.environ.get('MODEL_SERVING_ENDPOINT', '')
        self.model_name = os.environ.get('MODEL_NAME', 'databricks-gpt-oss-20b')
        self.model_max_tokens = int(os.environ.get('MODEL_MAX_TOKENS', '256'))
        
        # Validate configuration
        if not self.issuer_url:
            logger.warning("Okta issuer URL not configured")
        if not self.client_id:
            logger.warning("Okta client ID not configured")
        if not self.client_secret:
            logger.warning("Okta client secret not configured")
        if not self.databricks_server_hostname:
            logger.warning("Databricks SQL endpoint not fully configured")

config = Config()

def generate_pkce_pair():
    """Generate PKCE code verifier and challenge"""
    # Generate code verifier (43-128 characters)
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    
    # Generate code challenge (SHA256 hash of verifier, base64url encoded)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode('utf-8').rstrip('=')
    
    return code_verifier, code_challenge

def exchange_code_for_token(authorization_code):
    """Exchange authorization code for tokens using PKCE + client secret (Enhanced Web App flow)"""
    # Get code verifier from session
    code_verifier = session.get('code_verifier')
    if not code_verifier:
        raise Exception("No code verifier found in session")
    
    token_data = {
        'grant_type': 'authorization_code',
        'code': authorization_code,
        'redirect_uri': config.redirect_uri,
        'client_id': config.client_id,
        'client_secret': config.client_secret,  # Web App authentication
        'code_verifier': code_verifier,  # PKCE security
        'scope': config.oauth_scope
    }
    
    try:
        response = requests.post(
            f"{config.issuer_url}/v1/token",
            data=token_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Token exchange failed: {str(e)}")
        raise Exception(f"Failed to exchange authorization code: {str(e)}")

def exchange_for_workspace_token(federated_token):
    """Exchange federated token for Databricks workspace token"""
    workspace_url = f"https://{config.databricks_server_hostname}"
    
    workspace_data = {
        'subject_token': federated_token,
        'subject_token_type': 'urn:ietf:params:oauth:token-type:jwt',
        'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
        'scope': 'all-apis'
    }
    
    try:
        response = requests.post(
            f"{workspace_url}/oidc/v1/token",
            data=workspace_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Workspace token exchange failed: {str(e)}")
        raise Exception(f"Failed to exchange for workspace token: {str(e)}")

def refresh_access_token():
    """Use refresh token to get new access token from Okta (Web App flow)"""
    refresh_token = session.get('refresh_token')
    if not refresh_token:
        logger.error("No refresh token available")
        return False
    
    refresh_data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': config.client_id,
        'client_secret': config.client_secret,  # Required for Web Apps
        'scope': config.oauth_scope
    }
    
    try:
        logger.info("Refreshing access token using refresh token")
        response = requests.post(
            f"{config.issuer_url}/v1/token",
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

def refresh_workspace_token():
    """Refresh the Databricks workspace token using the current access token"""
    access_token = session.get('access_token')
    if not access_token:
        logger.error("No access token available for workspace token refresh")
        return False
    
    try:
        logger.info("Refreshing workspace token")
        workspace_response = exchange_for_workspace_token(access_token)
        session['workspace_token'] = workspace_response.get('access_token')
        logger.info("Workspace token refreshed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Workspace token refresh failed: {str(e)}")
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
    
    # First refresh the Okta access token
    if not refresh_access_token():
        logger.error("Failed to refresh access token")
        return False
    
    # Then refresh the workspace token with the new access token
    if not refresh_workspace_token():
        logger.error("Failed to refresh workspace token")
        return False
    
    logger.info("All tokens refreshed successfully")
    return True

def execute_sql_query(query, warehouse_id):
    """Execute SQL query on Databricks SQL endpoint"""
    try:
        # Get workspace token from session
        workspace_token = session.get('workspace_token')
        if not workspace_token:
            raise Exception("No workspace token available")
        
        workspace_url = f"https://{config.databricks_server_hostname}"
        
        # Create SQL execution request
        sql_data = {
            'warehouse_id': warehouse_id,
            'statement': query,
            'wait_timeout': '30s'
        }
        
        headers = {
            'Authorization': f'Bearer {workspace_token}',
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
    protected_endpoints = ['dashboard', 'sql_interface', 'execute_sql', 'chat_interface', 'send_message']
    
    if request.endpoint in protected_endpoints:
        # Check if user has tokens
        if 'access_token' not in session or 'workspace_token' not in session:
            logger.info("No tokens found, redirecting to login")
            return redirect(url_for('index'))
        
        # Check if tokens need refresh
        if not refresh_tokens_if_needed():
            logger.error("Token refresh failed, clearing session and redirecting to login")
            session.clear()
            return redirect(url_for('index'))

@app.route('/')
def index():
    """Main page - login or dashboard"""
    try:
        logger.info("Serving index page")
        
        # Check if user is authenticated
        if 'access_token' in session and 'workspace_token' in session:
            return redirect(url_for('databricks_interface'))
        
        return render_template('index.html')
        
    except Exception as e:
        logger.error(f"Error serving index page: {str(e)}")
        return f"Error: {str(e)}", 500

@app.route('/databricks')
def databricks_interface():
    """Databricks interface selection page for authenticated users"""
    if 'access_token' not in session or 'workspace_token' not in session:
        return redirect(url_for('index'))
    
    workspace_url = f"https://{config.databricks_server_hostname}"
    token_obtained = session.get('token_obtained')
    
    return render_template('databricks_interface.html',
                         workspace_url=workspace_url,
                         token_obtained=token_obtained,
                         model_name=config.model_name,
                         server_hostname=config.databricks_server_hostname)

@app.route('/login')
def login():
    """Initiate OAuth authorization (Web App flow with PKCE + Client Secret)"""
    try:
        # Generate state and nonce for security
        state = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        nonce = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        
        # Generate PKCE pair for enhanced security
        code_verifier, code_challenge = generate_pkce_pair()
        
        # Store state and code verifier in session for validation
        session['oauth_state'] = state
        session['code_verifier'] = code_verifier
        
        # Build authorization URL (Web App with PKCE)
        auth_params = {
            'client_id': config.client_id,
            'response_type': 'code',
            'scope': config.oauth_scope,
            'redirect_uri': config.redirect_uri,
            'state': state,
            'nonce': nonce,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }
        
        auth_url = f"{config.issuer_url}/v1/authorize?" + urlencode(auth_params)
        
        logger.info("Redirecting to OAuth authorization (PKCE + Client Secret)")
        return redirect(auth_url)
        
    except Exception as e:
        logger.error(f"Error initiating OAuth flow: {str(e)}")
        return f"Login error: {str(e)}", 500

@app.route('/callback')
def callback():
    """Handle OAuth callback"""
    try:
        # Get authorization code and state from callback
        authorization_code = request.args.get('code')
        state = request.args.get('state')
        
        if not authorization_code:
            return "Authorization code not received", 400
        
        # Validate state parameter
        if state != session.get('oauth_state'):
            logger.error("Invalid state parameter")
            return "Invalid state parameter", 400
        
        # Exchange code for tokens (Web App flow - uses client secret)
        logger.info("Exchanging authorization code for tokens")
        token_response = exchange_code_for_token(authorization_code)
        
        # Store tokens in session
        session['access_token'] = token_response.get('access_token')
        session['id_token'] = token_response.get('id_token')
        session['refresh_token'] = token_response.get('refresh_token')  # Session-independent!
        session['token_obtained'] = datetime.now().isoformat()
        
        # Exchange for workspace token
        federated_token = token_response.get('access_token')
        logger.info("Exchanging for workspace token")
        workspace_response = exchange_for_workspace_token(federated_token)
        
        session['workspace_token'] = workspace_response.get('access_token')
        session['workspace_url'] = f"https://{config.databricks_server_hostname}"
        
        # Clean up session
        session.pop('oauth_state', None)
        session.pop('code_verifier', None)
        
        logger.info("OAuth flow completed successfully (PKCE + Client Secret)")
        return redirect(url_for('databricks_interface'))
        
    except Exception as e:
        logger.error(f"Error processing OAuth callback: {str(e)}")
        return f"Callback error: {str(e)}", 500

@app.route('/sql')
def sql_interface():
    """SQL query interface"""
    if 'access_token' not in session or 'workspace_token' not in session:
        return redirect(url_for('index'))
    
    workspace_url = session.get('workspace_url')
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
        if 'workspace_token' not in session:
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

def call_model_serving_endpoint(messages, temperature=0.7, max_tokens=None):
    """Call Databricks model serving endpoint using OpenAI-compatible API"""
    try:
        # Get workspace token from session
        workspace_token = session.get('workspace_token')
        if not workspace_token:
            raise Exception("No workspace token available")
        
        # Set max_tokens from config if not provided
        if max_tokens is None:
            max_tokens = config.model_max_tokens
        
        base_url = f"https://{config.databricks_server_hostname}/serving-endpoints"
        logger.info(f"Calling model serving endpoint: {config.model_name} at {base_url}")
        logger.info(f"Request parameters - temperature: {temperature}, max_tokens: {max_tokens}")
        
        # Use the workspace token as the API key for Databricks model serving
        try:
            # Explicitly initialize OpenAI client with only supported parameters
            client = OpenAI(
                api_key=workspace_token,
                base_url=base_url,
                timeout=30.0,
                max_retries=2
            )
        except Exception as client_error:
            logger.error(f"Failed to create OpenAI client: {str(client_error)}")
            logger.error(f"OpenAI version: {OpenAI.__version__ if hasattr(OpenAI, '__version__') else 'unknown'}")
            raise Exception(f"OpenAI client initialization failed: {str(client_error)}")
        
        try:
            chat_completion = client.chat.completions.create(
                messages=messages,
                model=config.model_name,
                max_tokens=max_tokens,
                temperature=temperature
            )
        except Exception as api_error:
            logger.error(f"Model serving API call failed: {str(api_error)}")
            raise Exception(f"Model serving API error: {str(api_error)}")
        
        logger.info(f"Model serving call successful")
        response_content = chat_completion.choices[0].message.content
        logger.info(f"Response content type: {type(response_content)}")
        logger.info(f"Response content: {response_content}")
        
        # Handle structured response from Databricks model
        if isinstance(response_content, list):
            # Look for the text content in the structured response
            for item in response_content:
                if isinstance(item, dict) and item.get('type') == 'text':
                    return item.get('text', '')
            # If no text type found, try to extract any text content
            text_parts = []
            for item in response_content:
                if isinstance(item, dict):
                    if 'text' in item:
                        text_parts.append(item['text'])
                    elif 'summary' in item and isinstance(item['summary'], list):
                        for summary_item in item['summary']:
                            if isinstance(summary_item, dict) and 'text' in summary_item:
                                text_parts.append(summary_item['text'])
            return '\n'.join(text_parts) if text_parts else str(response_content)
        
        return response_content
        
    except Exception as e:
        logger.error(f"Model serving call failed: {str(e)}")
        raise

@app.route('/chat')
def chat_interface():
    """Chat interface with Databricks model"""
    if 'access_token' not in session or 'workspace_token' not in session:
        return redirect(url_for('index'))
    
    workspace_url = f"https://{config.databricks_server_hostname}"
    token_obtained = session.get('token_obtained')
    
    return render_template('chat_interface.html',
                         workspace_url=workspace_url,
                         token_obtained=token_obtained,
                         model_name=config.model_name,
                         server_hostname=config.databricks_server_hostname)

@app.route('/send-message', methods=['POST'])
def send_message():
    """Send message to the model and get response"""
    try:
        if 'workspace_token' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        data = request.json
        user_message = data.get('message', '').strip()
        chat_history = data.get('history', [])
        temperature = float(data.get('temperature', 0.7))
        max_tokens = int(data.get('max_tokens', config.model_max_tokens))
        
        if not user_message:
            return jsonify({'error': 'Missing message'}), 400
        
        # Build messages array for the model
        messages = []
        
        # Add system message if this is the first message
        if not chat_history:
            messages.append({
                "role": "system",
                "content": "You are a helpful AI assistant. Provide clear, accurate, and helpful responses."
            })
        
        # Add chat history
        for msg in chat_history:
            messages.append({
                "role": msg.get('role', 'user'),
                "content": msg.get('content', '')
            })
        
        # Add current user message
        messages.append({
            "role": "user",
            "content": user_message
        })
        
        # Call the model
        response_content = call_model_serving_endpoint(
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens
        )
        
        logger.info(f"Final response content type: {type(response_content)}")
        logger.info(f"Final response content: {response_content}")
        
        return jsonify({
            'success': True,
            'response': response_content,
            'timestamp': datetime.now().isoformat(),
            'model': config.model_name,
            'temperature': temperature,
            'max_tokens': max_tokens
        })
        
    except Exception as e:
        logger.error(f"Chat message error: {str(e)}")
        return jsonify({
            'success': False,
            'error': f"Chat failed: {str(e)}"
        }), 500

@app.route('/logout')
def logout():
    """Clear session and logout"""
    logger.info("User logging out")
    session.clear()
    return redirect(url_for('index'))

@app.route('/health')
def health():
    """Health check endpoint"""
    authenticated = 'access_token' in session and 'workspace_token' in session
    
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'authenticated': authenticated,
        'okta_configured': bool(config.issuer_url and config.client_id and config.client_secret),
        'databricks_configured': bool(config.databricks_server_hostname),
        'app_type': 'Web Application (PKCE + Client Secret + Session-Independent Refresh Tokens)'
    })

@app.route('/test-openai')
def test_openai():
    """Test OpenAI client initialization"""
    try:
        # Test basic OpenAI client creation
        test_client = OpenAI(
            api_key="test-key",
            base_url="https://api.openai.com/v1",
            timeout=30.0,
            max_retries=2
        )
        
        return jsonify({
            'success': True,
            'openai_version': openai.__version__,
            'client_created': True,
            'message': 'OpenAI client can be initialized successfully'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'openai_version': openai.__version__ if hasattr(openai, '__version__') else 'unknown',
            'message': 'OpenAI client initialization failed'
        }), 500

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
            'has_workspace_token': 'workspace_token' in session,
            'refresh_token_type': 'session_independent'
        })
    except Exception as e:
        return jsonify({'error': f'Error calculating token status: {str(e)}'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 6000))  # Different port from SPA
    debug = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    
    logger.info(f"Starting Web Application OAuth App on port {port}")
    logger.info(f"Client ID: {config.client_id}")
    logger.info(f"Client Secret: {'*' * len(config.client_secret) if config.client_secret else 'Not configured'}")
    logger.info(f"Databricks Server: {config.databricks_server_hostname}")
    logger.info(f"Redirect URI: {config.redirect_uri}")
    logger.info("🔄 Using Authorization Code Flow with PKCE + Client Secret (session-independent refresh tokens)")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
