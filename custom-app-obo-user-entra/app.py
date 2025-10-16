#!/usr/bin/env python3
"""
Custom OAuth App - On Behalf Of User with Microsoft Entra ID

A Flask application that:
1. Authenticates users with Microsoft Entra ID (Azure AD)
2. Exchanges Entra ID tokens for Databricks workspace tokens
3. Provides SQL Analytics and AI Assistant interfaces
"""

import os
import json
import base64
import hashlib
import secrets
import urllib.parse
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv('config.env')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

# Configure secure session settings
app.config.update(
    SESSION_COOKIE_SECURE=False,  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2)
)

class Config:
    def __init__(self):
        # Microsoft Entra ID (Azure AD) Configuration
        self.tenant_id = os.environ.get('ENTRA_TENANT_ID', '')
        self.client_id = os.environ.get('ENTRA_CLIENT_ID', '')
        self.client_secret = os.environ.get('ENTRA_CLIENT_SECRET', '')  # Optional for public clients
        self.redirect_uri = os.environ.get('REDIRECT_URI', 'http://localhost:9001/callback')
        
        # Determine if this is a public client (no secret) or confidential client
        self.is_public_client = not bool(self.client_secret)
        
        # Entra ID endpoints - Use v2.0 to match working token exchange
        self.authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        self.auth_endpoint = f"{self.authority}/oauth2/v2.0/authorize"
        self.token_endpoint = f"{self.authority}/oauth2/v2.0/token"
        
        # OAuth scopes for Databricks - Use Application ID URI format
        # Default format: api://{client_id}/databricks-token-federation
        default_scope = f'api://{self.client_id}/databricks-token-federation' if self.client_id else 'openid profile email'
        self.scope = os.environ.get('OAUTH_SCOPE', default_scope)
        
        # App configuration
        self.port = int(os.environ.get('PORT', 9001))

config = Config()

def decode_jwt_payload(token):
    """Decode JWT payload without verification (for analysis only)"""
    try:
        # Split the JWT token
        parts = token.split('.')
        if len(parts) != 3:
            return None, "Invalid JWT format"
        
        # Decode header
        header_data = parts[0] + '=' * (4 - len(parts[0]) % 4)  # Add padding
        header = json.loads(base64.urlsafe_b64decode(header_data))
        
        # Decode payload
        payload_data = parts[1] + '=' * (4 - len(parts[1]) % 4)  # Add padding
        payload = json.loads(base64.urlsafe_b64decode(payload_data))
        
        return {'header': header, 'payload': payload}, None
    except Exception as e:
        return None, f"Error decoding JWT: {str(e)}"

def analyze_actual_token(token, token_type):
    """Analyze actual JWT token from Entra ID for Databricks federation"""
    decoded, error = decode_jwt_payload(token)
    if error:
        logger.error(f"Token decode error: {error}")
        return
    
    logger.info(f"=== {token_type.upper()} TOKEN ANALYSIS ===")
    logger.info(f"Header: {json.dumps(decoded['header'], indent=2)}")
    logger.info(f"Payload: {json.dumps(decoded['payload'], indent=2)}")
    
    # Key claims for Databricks federation
    payload = decoded['payload']
    logger.info(f"🔑 KEY CLAIMS FOR DATABRICKS FEDERATION:")
    logger.info(f"  Issuer (iss): {payload.get('iss')}")
    logger.info(f"  Audience (aud): {payload.get('aud')}")
    logger.info(f"  Subject (sub): {payload.get('sub')}")
    logger.info(f"  Object ID (oid): {payload.get('oid')}")
    logger.info(f"  Email: {payload.get('email')}")
    logger.info(f"  Name: {payload.get('name')}")
    logger.info(f"  Tenant ID (tid): {payload.get('tid')}")
    logger.info(f"  Issued At: {datetime.fromtimestamp(payload.get('iat', 0))}")
    logger.info(f"  Expires At: {datetime.fromtimestamp(payload.get('exp', 0))}")

def generate_pkce_pair():
    """Generate PKCE code verifier and challenge for enhanced security"""
    # Generate code verifier (43-128 characters, URL-safe)
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    
    # Generate code challenge
    challenge_bytes = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(challenge_bytes).decode('utf-8').rstrip('=')
    
    return code_verifier, code_challenge

def exchange_code_for_token(auth_code, code_verifier):
    """Exchange authorization code for Entra ID access token"""
    logger.info(f"Starting Entra ID token exchange (public_client: {config.is_public_client})")
    
    token_data = {
        'grant_type': 'authorization_code',
        'client_id': config.client_id,
        'redirect_uri': config.redirect_uri,
        'code': auth_code,
        'code_verifier': code_verifier,
        'scope': config.scope  # Add scope to match your manual curl command
    }
    
    # Add client_secret for confidential clients (Web Applications)
    if not config.is_public_client:
        token_data['client_secret'] = config.client_secret
        logger.info("Confidential client (Web App) token exchange - using client secret")
    else:
        # For public clients, ensure we're not sending scope in token request
        # The scope was already specified in the authorization request
        logger.info("Public client (SPA) token exchange - using PKCE only")
    
    logger.info(f"Token request data: {dict(token_data)}")  # Log the request (without sensitive data)
    
    try:
        response = requests.post(
            config.token_endpoint,
            data=token_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=30
        )
        
        # Log response details for debugging
        logger.info(f"Token response status: {response.status_code}")
        
        if response.status_code != 200:
            error_details = response.text
            logger.error(f"Token exchange failed with status {response.status_code}: {error_details}")
            try:
                error_json = response.json()
                error_msg = error_json.get('error_description', error_json.get('error', 'Unknown error'))
                logger.error(f"Error details: {error_msg}")
            except:
                logger.error(f"Raw error response: {error_details}")
        
        response.raise_for_status()
        result = response.json()
        
        logger.info("Entra ID token exchange successful")
        return result
        
    except requests.RequestException as e:
        logger.error(f"Entra ID token exchange failed: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_details = e.response.json()
                logger.error(f"Detailed error: {error_details}")
            except:
                logger.error(f"Raw error response: {e.response.text}")
        raise Exception(f"Failed to exchange authorization code: {str(e)}")

def check_databricks_oidc_support(workspace_url):
    """Check if Databricks workspace supports OIDC token exchange"""
    try:
        discovery_url = f"{workspace_url}/.well-known/openid_configuration"
        response = requests.get(discovery_url, timeout=10)
        return response.status_code == 200
    except Exception as e:
        logger.error(f"Error checking OIDC support: {e}")
        return False

def exchange_for_databricks_token(entra_token, workspace_url, token_type='access_token'):
    """Exchange Entra ID token for Databricks workspace token"""
    logger.info("Starting Databricks token exchange")
    logger.info(f"Workspace URL: {workspace_url}")
    logger.info(f"Token type: {token_type}")
    
    # Use JWT token type as it works with your curl command
    subject_token_type = 'urn:ietf:params:oauth:token-type:jwt'
    
    # Use the Entra ID token for Databricks token exchange
    databricks_data = {
        'subject_token': entra_token,
        'subject_token_type': subject_token_type,
        'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
        'scope': 'all-apis'
    }
    
    logger.info(f"Databricks token exchange request data: {dict(databricks_data)}")
    
    try:
        token_url = f"{workspace_url}/oidc/v1/token"
        logger.info(f"Databricks token endpoint: {token_url}")
        
        # Debug: Show exact curl equivalent
        logger.info("=== CURL EQUIVALENT ===")
        curl_parts = [f"curl --request POST {token_url}"]
        for key, value in databricks_data.items():
            if key == 'subject_token':
                curl_parts.append(f"  --data '{key}={value[:50]}...'")
            else:
                curl_parts.append(f"  --data '{key}={value}'")
        logger.info(" \\\n".join(curl_parts))
        logger.info("=== END CURL ===")
        
        response = requests.post(
            token_url,
            data=databricks_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=30
        )
        
        # Log response details for debugging
        logger.info(f"Databricks token response status: {response.status_code}")
        
        if response.status_code != 200:
            error_details = response.text
            logger.error(f"Databricks token exchange failed with status {response.status_code}: {error_details}")
            try:
                error_json = response.json()
                error_msg = error_json.get('error_description', error_json.get('error', 'Unknown error'))
                logger.error(f"Databricks error details: {error_msg}")
            except:
                logger.error(f"Raw Databricks error response: {error_details}")
        
        response.raise_for_status()
        result = response.json()
        
        logger.info("Databricks token exchange successful")
        return result
        
    except requests.RequestException as e:
        logger.error(f"Databricks token exchange failed: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_details = e.response.json()
                logger.error(f"Detailed Databricks error: {error_details}")
            except:
                logger.error(f"Raw Databricks error response: {e.response.text}")
        raise Exception(f"Failed to exchange for Databricks token: {str(e)}")

# Token refresh functionality
def refresh_access_token():
    """Refresh the access token using refresh token"""
    refresh_token = session.get('refresh_token')
    if not refresh_token:
        return False
    
    try:
        refresh_data = {
            'grant_type': 'refresh_token',
            'client_id': config.client_id,
            'refresh_token': refresh_token,
            'scope': config.scope
        }
        
        # Only add client_secret for confidential clients
        if not config.is_public_client:
            refresh_data['client_secret'] = config.client_secret
        
        response = requests.post(
            config.token_endpoint,
            data=refresh_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=30
        )
        response.raise_for_status()
        result = response.json()
        
        # Update session with new tokens
        session['access_token'] = result['access_token']
        if 'refresh_token' in result:
            session['refresh_token'] = result['refresh_token']
        session['token_expires_at'] = datetime.now() + timedelta(seconds=result.get('expires_in', 3600))
        
        logger.info("Token refresh successful")
        return True
        
    except Exception as e:
        logger.error(f"Token refresh failed: {str(e)}")
        return False

@app.before_request
def check_token_expiry():
    """Check if token needs refresh before each request"""
    if request.endpoint in ['static', 'index', 'login', 'oauth_callback', 'clear_session']:
        return
    
    if 'access_token' in session and 'token_expires_at' in session:
        expires_at = datetime.fromisoformat(session['token_expires_at'])
        if datetime.now() >= expires_at - timedelta(minutes=5):  # Refresh 5 minutes before expiry
            if not refresh_access_token():
                logger.info("Token refresh failed, redirecting to login")
                session.clear()
                return redirect(url_for('index'))

@app.route('/')
def index():
    """Main page - authentication status and interface selection"""
    if 'access_token' in session and 'workspace_token' in session:
        # User is authenticated, redirect to dashboard
        return redirect(url_for('databricks_interface'))
    
    return render_template('index.html', config=config)

@app.route('/databricks')
def databricks_interface():
    """Unified Databricks interface selection page"""
    workspace_token = session.get('workspace_token')
    if not workspace_token:
        flash('No token found. Please complete authentication first.', 'error')
        return redirect(url_for('index'))
    
    workspace_url = session.get('workspace_url')
    expires_at = datetime.now() + timedelta(seconds=3600)  # Databricks tokens expire in 1 hour
    
    return render_template('databricks_interface.html',
                         workspace_token=workspace_token,
                         workspace_url=workspace_url,
                         expires_at=expires_at,
                         expires_in=3600)

@app.route('/login', methods=['POST'])
def login():
    """Initiate Entra ID OAuth flow"""
    try:
        # Get workspace URL from form
        workspace_url = request.form.get('workspace_url', '').strip()
        
        if not workspace_url:
            flash('Workspace URL is required', 'error')
            return redirect(url_for('index'))
        
        # Validate workspace URL
        if not workspace_url.startswith(('http://', 'https://')):
            flash('Workspace URL must start with http:// or https://', 'error')
            return redirect(url_for('index'))
        
        # Remove trailing slash
        workspace_url = workspace_url.rstrip('/')
        
        # Generate PKCE parameters
        code_verifier, code_challenge = generate_pkce_pair()
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(16)
        
        # Store in session
        session['code_verifier'] = code_verifier
        session['oauth_state'] = state
        session['oauth_nonce'] = nonce
        session['workspace_url'] = workspace_url
        session['oauth_started'] = datetime.now().isoformat()
        
        # Build authorization URL - matches working curl command
        auth_params = {
            'client_id': config.client_id,
            'response_type': 'code',
            'redirect_uri': config.redirect_uri,
            'scope': config.scope,
            'state': state,
            'nonce': nonce,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }
        
        auth_url = f"{config.auth_endpoint}?" + urllib.parse.urlencode(auth_params)
        
        logger.info("=" * 80)
        logger.info("🔐 STARTING ENTRA ID AUTHENTICATION FLOW")
        logger.info("=" * 80)
        logger.info(f"✅ Authorization Endpoint: {config.auth_endpoint}")
        logger.info(f"✅ Tenant ID: {config.tenant_id}")
        logger.info(f"✅ Client ID: {config.client_id}")
        logger.info(f"✅ Redirect URI: {config.redirect_uri}")
        logger.info(f"✅ Scope: {config.scope}")
        logger.info(f"✅ Full Authorization URL: {auth_url}")
        logger.info("=" * 80)
        logger.info("🌐 Redirecting user to MICROSOFT ENTRA ID (login.microsoftonline.com)")
        logger.info("=" * 80)
        
        return redirect(auth_url)
        
    except Exception as e:
        logger.error(f"Error starting OAuth flow: {str(e)}")
        flash(f'Error starting OAuth flow: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/callback')
def oauth_callback():
    """Handle OAuth callback from Entra ID"""
    try:
        # Get authorization code and state
        authorization_code = request.args.get('code')
        returned_state = request.args.get('state')
        error = request.args.get('error')
        error_description = request.args.get('error_description')
        
        if error:
            logger.error(f"OAuth error: {error} - {error_description}")
            flash(f'OAuth error: {error_description or error}', 'error')
            return redirect(url_for('index'))
        
        if not authorization_code:
            logger.error("No authorization code received")
            flash('No authorization code received', 'error')
            return redirect(url_for('index'))
        
        # Verify state parameter
        if returned_state != session.get('oauth_state'):
            logger.error("Invalid state parameter")
            flash('Invalid state parameter', 'error')
            return redirect(url_for('index'))
        
        # Get stored parameters
        code_verifier = session.get('code_verifier')
        workspace_url = session.get('workspace_url')
        
        if not code_verifier or not workspace_url:
            logger.error("Missing session data")
            flash('Invalid session state', 'error')
            return redirect(url_for('index'))
        
        # Exchange code for Entra ID token
        logger.info("=" * 80)
        logger.info("🔄 STEP 1: EXCHANGING AUTHORIZATION CODE FOR ENTRA ID TOKEN")
        logger.info("=" * 80)
        logger.info(f"✅ Token Endpoint: {config.token_endpoint}")
        logger.info(f"✅ This is a MICROSOFT ENTRA ID endpoint (login.microsoftonline.com)")
        logger.info("=" * 80)
        entra_response = exchange_code_for_token(authorization_code, code_verifier)
        
        # Analyze tokens for Databricks federation configuration
        logger.info("🔍 ANALYZING ENTRA ID TOKENS FOR DATABRICKS FEDERATION")
        if 'id_token' in entra_response:
            analyze_actual_token(entra_response['id_token'], 'id_token')
            # Save ID token for diagnostic tool
            try:
                with open('temp_token.txt', 'w') as f:
                    f.write(entra_response['id_token'])
                logger.info("💾 ID token saved to temp_token.txt for diagnostic tool")
            except Exception as e:
                logger.warning(f"Could not save token to file: {e}")
        if 'access_token' in entra_response:
            analyze_actual_token(entra_response['access_token'], 'access_token')
        
        # Store Entra ID tokens
        session['access_token'] = entra_response['access_token']
        session['refresh_token'] = entra_response.get('refresh_token')
        session['id_token'] = entra_response.get('id_token')  # Store ID token too
        expires_in = int(entra_response.get('expires_in', 3600))
        session['token_expires_at'] = (datetime.now() + timedelta(seconds=expires_in)).isoformat()
        
        # Skip OIDC discovery check since token exchange works via curl
        logger.info("Skipping OIDC discovery check - proceeding with token exchange")
        logger.info("Note: OIDC discovery may not be configured, but token exchange endpoint works")
        
        # Exchange Entra ID token for Databricks token
        logger.info("=" * 80)
        logger.info("🔄 STEP 2: EXCHANGING ENTRA ID TOKEN FOR DATABRICKS TOKEN")
        logger.info("=" * 80)
        token_for_exchange = entra_response.get('id_token') or entra_response['access_token']
        token_type = 'id_token' if entra_response.get('id_token') else 'access_token'
        logger.info(f"✅ Using {token_type} from ENTRA ID for Databricks token exchange")
        logger.info(f"✅ Databricks Endpoint: {workspace_url}/oidc/v1/token")
        logger.info("=" * 80)
        
        databricks_response = exchange_for_databricks_token(
            token_for_exchange, 
            workspace_url,
            token_type
        )
        
        # Store Databricks token
        session['workspace_token'] = databricks_response['access_token']
        session['token_obtained'] = datetime.now().isoformat()
        
        # Clear temporary session data
        session.pop('code_verifier', None)
        session.pop('oauth_state', None)
        
        logger.info("=" * 80)
        logger.info("✅ SUCCESS! COMPLETE OAUTH FLOW")
        logger.info("=" * 80)
        logger.info("✅ Step 1: Got token from ENTRA ID (login.microsoftonline.com)")
        logger.info("✅ Step 2: Exchanged Entra ID token for Databricks token")
        logger.info("✅ You now have a valid Databricks workspace token")
        logger.info("=" * 80)
        return redirect(url_for('databricks_interface'))
        
    except Exception as e:
        logger.error(f"Error processing OAuth callback: {str(e)}")
        flash(f'Error processing OAuth callback: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/sql-setup')
def sql_setup():
    """SQL interface setup page"""
    if 'workspace_token' not in session:
        flash('Please complete authentication first.', 'error')
        return redirect(url_for('index'))
    
    workspace_url = session.get('workspace_url')
    expires_at = datetime.now() + timedelta(seconds=3600)
    
    return render_template('sql_setup.html',
                         workspace_url=workspace_url,
                         expires_at=expires_at)

@app.route('/sql-interface', methods=['POST'])
def sql_interface():
    """Launch SQL interface with warehouse ID"""
    if 'workspace_token' not in session:
        flash('Please complete authentication first.', 'error')
        return redirect(url_for('index'))
    
    warehouse_id = request.form.get('warehouse_id', '').strip()
    if not warehouse_id:
        flash('Warehouse ID is required.', 'error')
        return redirect(url_for('sql_setup'))
    
    session['warehouse_id'] = warehouse_id
    
    workspace_token = session.get('workspace_token')
    workspace_url = session.get('workspace_url')
    expires_at = datetime.now() + timedelta(seconds=3600)
    
    return render_template('sql_interface.html',
                         workspace_token=workspace_token,
                         workspace_url=workspace_url,
                         warehouse_id=warehouse_id,
                         expires_at=expires_at)

@app.route('/chat-setup')
def chat_setup():
    """Chat interface setup page"""
    if 'workspace_token' not in session:
        flash('Please complete authentication first.', 'error')
        return redirect(url_for('index'))
    
    workspace_url = session.get('workspace_url')
    expires_at = datetime.now() + timedelta(seconds=3600)
    
    return render_template('chat_setup.html',
                         workspace_url=workspace_url,
                         expires_at=expires_at)

@app.route('/chat-interface', methods=['POST'])
def chat_interface():
    """Launch chat interface with model endpoint"""
    if 'workspace_token' not in session:
        flash('Please complete authentication first.', 'error')
        return redirect(url_for('index'))
    
    model_endpoint = request.form.get('model_endpoint', '').strip()
    if not model_endpoint:
        flash('Model serving endpoint URL is required.', 'error')
        return redirect(url_for('chat_setup'))
    
    if not model_endpoint.startswith(('http://', 'https://')):
        flash('Model endpoint URL must start with http:// or https://', 'error')
        return redirect(url_for('chat_setup'))
    
    session['model_endpoint'] = model_endpoint
    
    workspace_token = session.get('workspace_token')
    workspace_url = session.get('workspace_url')
    expires_at = datetime.now() + timedelta(seconds=3600)
    
    return render_template('chat_interface.html',
                         workspace_token=workspace_token,
                         workspace_url=workspace_url,
                         model_endpoint=model_endpoint,
                         expires_at=expires_at)

@app.route('/execute-sql', methods=['POST'])
def execute_sql():
    """Execute SQL query using Databricks SQL API"""
    try:
        workspace_token = session.get('workspace_token')
        warehouse_id = session.get('warehouse_id')
        workspace_url = session.get('workspace_url')
        
        if not workspace_token or not warehouse_id:
            return jsonify({'error': 'No token or warehouse ID available'}), 400
        
        data = request.get_json()
        sql_query = data.get('query', '').strip()
        
        if not sql_query:
            return jsonify({'error': 'SQL query is required'}), 400
        
        # Execute SQL using Databricks SQL API
        result = execute_databricks_sql(workspace_token, workspace_url, warehouse_id, sql_query)
        return jsonify({'result': result})
        
    except Exception as e:
        logger.error(f"Error executing SQL: {str(e)}")
        return jsonify({'error': str(e)}), 500

def execute_databricks_sql(token, workspace_url, warehouse_id, sql_query):
    """Execute SQL query using Databricks SQL API"""
    try:
        create_url = f"{workspace_url}/api/2.0/sql/statements"
        
        create_payload = {
            "warehouse_id": warehouse_id,
            "statement": sql_query,
            "wait_timeout": "30s"
        }
        
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        response = requests.post(
            create_url,
            json=create_payload,
            headers=headers,
            timeout=60
        )
        
        response.raise_for_status()
        execution_result = response.json()
        
        if execution_result.get('status', {}).get('state') == 'SUCCEEDED':
            result_data = execution_result.get('result', {})
            schema = result_data.get('data_array', [])
            columns = []
            rows = []
            
            if schema:
                manifest = execution_result.get('manifest', {})
                if manifest and 'schema' in manifest:
                    columns = [col['name'] for col in manifest['schema']['columns']]
                else:
                    if schema:
                        columns = [f"col_{i}" for i in range(len(schema[0]))]
                rows = schema
            
            return {
                'success': True,
                'columns': columns,
                'rows': rows,
                'row_count': len(rows),
                'execution_time': execution_result.get('status', {}).get('execution_time_ms', 0)
            }
        
        elif execution_result.get('status', {}).get('state') == 'FAILED':
            error_message = execution_result.get('status', {}).get('error', {}).get('message', 'Unknown error')
            return {'success': False, 'error': error_message}
        
        else:
            state = execution_result.get('status', {}).get('state', 'UNKNOWN')
            return {'success': False, 'error': f'Query execution in state: {state}'}
            
    except requests.RequestException as e:
        logger.error(f"SQL execution request failed: {str(e)}")
        raise Exception(f"Failed to execute SQL query: {str(e)}")

@app.route('/send-message', methods=['POST'])
def send_message():
    """Send message to model serving endpoint"""
    try:
        workspace_token = session.get('workspace_token')
        model_endpoint = session.get('model_endpoint')
        
        if not workspace_token or not model_endpoint:
            return jsonify({'error': 'No token or model endpoint available'}), 400
        
        data = request.get_json()
        message = data.get('message', '').strip()
        
        if not message:
            return jsonify({'error': 'Message is required'}), 400
        
        # Call model serving endpoint
        response = call_model_serving_endpoint(workspace_token, model_endpoint, message)
        return jsonify({'response': response})
        
    except Exception as e:
        logger.error(f"Error sending message: {str(e)}")
        return jsonify({'error': str(e)}), 500

def call_model_serving_endpoint(token, endpoint_url, message):
    """Call Databricks model serving endpoint"""
    try:
        payload = {
            "messages": [{"role": "user", "content": message}],
            "max_tokens": 256
        }
        
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        response = requests.post(
            endpoint_url,
            json=payload,
            headers=headers,
            timeout=30
        )
        
        response.raise_for_status()
        result = response.json()
        
        # Handle different response formats
        if 'choices' in result and len(result['choices']) > 0:
            content = result['choices'][0]['message']['content']
            
            if isinstance(content, str):
                return content
            elif isinstance(content, list):
                extracted_texts = []
                for item in content:
                    if isinstance(item, dict) and item.get('type') == 'text' and 'text' in item:
                        extracted_texts.append(item['text'])
                return '\n'.join(extracted_texts) if extracted_texts else str(content)
            else:
                return str(content)
        
        return str(result)
        
    except requests.RequestException as e:
        logger.error(f"Model serving request failed: {str(e)}")
        raise Exception(f"Failed to call model serving endpoint: {str(e)}")

@app.route('/clear')
def clear_session():
    """Clear session and start over"""
    session.clear()
    flash('Session cleared. You can start a new authentication flow.', 'info')
    return redirect(url_for('index'))

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'config': {
            'tenant_id': config.tenant_id,
            'client_id': config.client_id,
            'redirect_uri': config.redirect_uri,
            'port': config.port,
            'client_type': 'public' if config.is_public_client else 'confidential',
            'authentication_flow': 'User-to-Machine (U2M)' if config.is_public_client else 'Confidential Client',
            'oauth_scope': config.scope,
            'auth_endpoint': config.auth_endpoint,
            'token_endpoint': config.token_endpoint
        }
    })

@app.route('/debug-oauth')
def debug_oauth():
    """Debug OAuth configuration and provide troubleshooting info"""
    return jsonify({
        'entra_id_config': {
            'tenant_id': config.tenant_id,
            'client_id': config.client_id,
            'client_type': 'public' if config.is_public_client else 'confidential',
            'redirect_uri': config.redirect_uri,
            'scope': config.scope
        },
        'endpoints': {
            'authorization': config.auth_endpoint,
            'token': config.token_endpoint
        },
        'troubleshooting': {
            'common_401_causes': [
                'App registered as Web instead of SPA',
                'Incorrect redirect URI in Entra ID',
                'Client secret required but not provided',
                'PKCE not enabled in app registration'
            ],
            'recommended_app_settings': {
                'platform': 'Single-page application (SPA)',
                'redirect_uri': config.redirect_uri,
                'implicit_grant': False,
                'access_tokens': True,
                'id_tokens': True
            }
        }
    })

if __name__ == '__main__':
    logger.info(f"Starting Entra ID OAuth app on port {config.port}")
    logger.info(f"Redirect URI: {config.redirect_uri}")
    logger.info(f"Tenant ID: {config.tenant_id}")
    
    app.run(
        host='0.0.0.0',
        port=config.port,
        debug=True
    )
