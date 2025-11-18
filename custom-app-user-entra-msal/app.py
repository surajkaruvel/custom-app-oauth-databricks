#!/usr/bin/env python3
"""
Custom OAuth App - On Behalf Of User with Microsoft Entra ID (MSAL)

A Flask application that:
1. Authenticates users with Microsoft Entra ID (Azure AD) using MSAL
2. Exchanges Entra ID tokens for Databricks workspace tokens
3. Provides SQL Analytics and AI Assistant interfaces

This version uses the Microsoft Authentication Library (MSAL) for Python,
which simplifies OAuth flows and provides better token management.
"""

import os
import json
import base64
import secrets
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import requests
from dotenv import load_dotenv
import msal

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
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    # Increase max cookie size warning threshold (default is 4093)
    # Note: We optimize by not storing all tokens, only workspace token
    MAX_COOKIE_SIZE=4093
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
        
        # Entra ID authority
        self.authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        
        # OAuth scopes for Databricks
        default_scope = f'api://{self.client_id}/databricks-token-federation' if self.client_id else 'openid profile email'
        self.scope = os.environ.get('OAUTH_SCOPE', default_scope)
        self.scopes = [self.scope]  # MSAL expects a list
        
        # App configuration
        self.port = int(os.environ.get('PORT', 9001))

config = Config()

def get_msal_app():
    """
    Create and return an MSAL application instance.
    MSAL handles all OAuth mechanics including PKCE, token caching, etc.
    """
    if config.is_public_client:
        # Public client (SPA) - no client secret
        logger.info("Creating MSAL PublicClientApplication (U2M flow)")
        return msal.PublicClientApplication(
            client_id=config.client_id,
            authority=config.authority,
        )
    else:
        # Confidential client (Web App) - with client secret
        logger.info("Creating MSAL ConfidentialClientApplication (Web App flow)")
        return msal.ConfidentialClientApplication(
            client_id=config.client_id,
            client_credential=config.client_secret,
            authority=config.authority,
        )

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

def analyze_token(token, token_type):
    """Analyze JWT token for debugging"""
    decoded, error = decode_jwt_payload(token)
    if error:
        logger.error(f"Token decode error: {error}")
        return
    
    logger.info("=" * 80)
    logger.info(f"📋 {token_type.upper()} TOKEN ANALYSIS")
    logger.info("=" * 80)
    
    # Log full token for external analysis
    logger.info(f"🔑 Full {token_type} token (first 100 chars): {token[:100]}...")
    logger.info(f"🔑 Full {token_type} token (last 50 chars): ...{token[-50:]}")
    logger.info(f"\n📝 To decode this token, visit: https://jwt.ms")
    
    # Log header and payload
    logger.info(f"\n📋 Header: {json.dumps(decoded['header'], indent=2)}")
    logger.info(f"\n📋 Payload: {json.dumps(decoded['payload'], indent=2)}")
    
    # Key claims for Databricks federation
    payload = decoded['payload']
    logger.info(f"\n🔑 KEY CLAIMS FOR DATABRICKS FEDERATION:")
    logger.info(f"  ✓ Issuer (iss): {payload.get('iss')}")
    logger.info(f"  ✓ Audience (aud): {payload.get('aud')}")
    logger.info(f"  ✓ Subject (sub): {payload.get('sub')}")
    logger.info(f"  ✓ Object ID (oid): {payload.get('oid')}")
    logger.info(f"  ✓ Email: {payload.get('email')}")
    logger.info(f"  ✓ Preferred Username: {payload.get('preferred_username')}")
    logger.info(f"  ✓ Name: {payload.get('name')}")
    logger.info(f"  ✓ Tenant ID (tid): {payload.get('tid')}")
    logger.info(f"  ✓ Issued At: {datetime.fromtimestamp(payload.get('iat', 0))}")
    logger.info(f"  ✓ Expires At: {datetime.fromtimestamp(payload.get('exp', 0))}")
    
    # Log token claims for debugging Databricks federation
    logger.info(f"\n📋 TOKEN CLAIMS FOR DATABRICKS FEDERATION:")
    logger.info(f"  Issuer (iss): {payload.get('iss')}")
    logger.info(f"  Audience (aud): {payload.get('aud')}")
    logger.info(f"\n💡 TIP: If token exchange fails with 'invalid_grant':")
    logger.info(f"     - Verify issuer matches: https://login.microsoftonline.com/{{YOUR_TENANT_ID}}/v2.0")
    logger.info(f"     - Verify audience matches your configured client ID")
    logger.info(f"     - Ensure Databricks federation policy is configured correctly")
    
    logger.info("=" * 80)

def get_token_from_cache():
    """
    Try to retrieve token from MSAL's token cache.
    MSAL automatically handles token caching and refresh.
    """
    msal_app = get_msal_app()
    accounts = msal_app.get_accounts()
    
    if accounts:
        # Try to acquire token silently
        result = msal_app.acquire_token_silent(
            scopes=config.scopes,
            account=accounts[0]
        )
        if result and "access_token" in result:
            logger.info("Token acquired from cache")
            return result
    
    return None

def exchange_for_databricks_token(entra_token, workspace_url):
    """Exchange Entra ID token for Databricks workspace token"""
    logger.info("Starting Databricks token exchange")
    logger.info(f"Workspace URL: {workspace_url}")
    
    # Use JWT token type for Databricks federation
    subject_token_type = 'urn:ietf:params:oauth:token-type:jwt'
    
    # Build token exchange request (RFC 8693)
    databricks_data = {
        'subject_token': entra_token,
        'subject_token_type': subject_token_type,
        'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
        'scope': 'all-apis'
    }
    
    try:
        token_url = f"{workspace_url}/oidc/v1/token"
        logger.info(f"Databricks token endpoint: {token_url}")
        
        response = requests.post(
            token_url,
            data=databricks_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=30
        )
        
        logger.info(f"Databricks token response status: {response.status_code}")
        
        if response.status_code != 200:
            error_details = response.text
            logger.error(f"Databricks token exchange failed: {error_details}")
            try:
                error_json = response.json()
                error_msg = error_json.get('error_description', error_json.get('error', 'Unknown error'))
                logger.error(f"Databricks error details: {error_msg}")
            except:
                logger.error(f"Raw Databricks error: {error_details}")
        
        response.raise_for_status()
        result = response.json()
        
        logger.info("Databricks token exchange successful")
        return result
        
    except requests.RequestException as e:
        logger.error(f"Databricks token exchange failed: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_details = e.response.json()
                logger.error(f"Detailed error: {error_details}")
            except:
                logger.error(f"Raw error: {e.response.text}")
        raise Exception(f"Failed to exchange for Databricks token: {str(e)}")

@app.route('/')
def index():
    """Main page - authentication status and interface selection"""
    if 'workspace_token' in session:
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
    """Initiate Entra ID OAuth flow using MSAL"""
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
        
        # Store workspace URL in session
        session['workspace_url'] = workspace_url
        
        # Use MSAL to initiate the authorization flow
        msal_app = get_msal_app()
        
        # Generate a unique state parameter for CSRF protection
        state = secrets.token_urlsafe(32)
        session['oauth_state'] = state
        
        # Build authorization request URL
        # MSAL automatically handles PKCE for public clients
        auth_url = msal_app.get_authorization_request_url(
            scopes=config.scopes,
            state=state,
            redirect_uri=config.redirect_uri
        )
        
        logger.info("=" * 80)
        logger.info("🔐 STARTING ENTRA ID AUTHENTICATION FLOW (MSAL)")
        logger.info("=" * 80)
        logger.info(f"✅ Authority: {config.authority}")
        logger.info(f"✅ Client ID: {config.client_id}")
        logger.info(f"✅ Client Type: {'Public (U2M)' if config.is_public_client else 'Confidential (Web App)'}")
        logger.info(f"✅ Redirect URI: {config.redirect_uri}")
        logger.info(f"✅ Scope: {config.scope}")
        logger.info(f"✅ MSAL Library: Handling PKCE, state, and nonce automatically")
        logger.info("=" * 80)
        logger.info("🌐 Redirecting user to MICROSOFT ENTRA ID")
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
        # Check for errors
        error = request.args.get('error')
        error_description = request.args.get('error_description')
        
        if error:
            logger.error(f"OAuth error: {error} - {error_description}")
            flash(f'OAuth error: {error_description or error}', 'error')
            return redirect(url_for('index'))
        
        # Get authorization code
        authorization_code = request.args.get('code')
        returned_state = request.args.get('state')
        
        if not authorization_code:
            logger.error("No authorization code received")
            flash('No authorization code received', 'error')
            return redirect(url_for('index'))
        
        # Verify state parameter
        if returned_state != session.get('oauth_state'):
            logger.error("Invalid state parameter")
            flash('Invalid state parameter - possible CSRF attack', 'error')
            return redirect(url_for('index'))
        
        workspace_url = session.get('workspace_url')
        if not workspace_url:
            logger.error("Missing workspace URL in session")
            flash('Invalid session state', 'error')
            return redirect(url_for('index'))
        
        # Use MSAL to exchange authorization code for token
        logger.info("=" * 80)
        logger.info("🔄 STEP 1: EXCHANGING AUTHORIZATION CODE FOR ENTRA ID TOKEN (MSAL)")
        logger.info("=" * 80)
        
        msal_app = get_msal_app()
        
        # MSAL handles all token exchange mechanics
        result = msal_app.acquire_token_by_authorization_code(
            code=authorization_code,
            scopes=config.scopes,
            redirect_uri=config.redirect_uri
        )
        
        if "error" in result:
            error_msg = result.get("error_description", result.get("error"))
            logger.error(f"MSAL token exchange error: {error_msg}")
            flash(f'Token exchange error: {error_msg}', 'error')
            return redirect(url_for('index'))
        
        if "access_token" not in result:
            logger.error("No access token in MSAL result")
            flash('Failed to obtain access token', 'error')
            return redirect(url_for('index'))
        
        logger.info("✅ MSAL token exchange successful")
        logger.info(f"Token type: {result.get('token_type', 'Bearer')}")
        logger.info(f"Expires in: {result.get('expires_in', 'unknown')} seconds")
        logger.info(f"Scopes: {result.get('scope', 'unknown')}")
        
        # Store only essential tokens in session (to avoid cookie size limits)
        # We'll use access_token for Databricks exchange, then can discard it
        # Note: Not storing id_token in session to save space
        session['entra_access_token'] = result['access_token']
        if result.get('refresh_token'):
            session['refresh_token'] = result.get('refresh_token')
        
        # Calculate token expiration
        expires_in = int(result.get('expires_in', 3600))
        session['token_expires_at'] = (datetime.now() + timedelta(seconds=expires_in)).isoformat()
        
        # Analyze both tokens if available
        if result.get('access_token'):
            logger.info("\n" + "=" * 80)
            logger.info("🔍 ANALYZING ACCESS TOKEN FROM ENTRA ID")
            logger.info("=" * 80)
            analyze_token(result['access_token'], 'access_token')
            
        if result.get('id_token'):
            logger.info("\n" + "=" * 80)
            logger.info("🔍 ANALYZING ID TOKEN FROM ENTRA ID")
            logger.info("=" * 80)
            analyze_token(result['id_token'], 'id_token')
        
        # Decide which token to use for Databricks exchange
        # IMPORTANT: Use ACCESS TOKEN for Databricks (not ID token)
        # Access token has the correct audience for Databricks federation
        token_for_exchange = result.get('access_token') or result.get('id_token')
        token_type = 'access_token' if result.get('access_token') else 'id_token'
        
        # Exchange Entra ID token for Databricks token
        logger.info("\n" + "=" * 80)
        logger.info("🔄 STEP 2: EXCHANGING ENTRA ID TOKEN FOR DATABRICKS TOKEN")
        logger.info("=" * 80)
        logger.info(f"✅ Using {token_type.upper()} from ENTRA ID for Databricks exchange")
        logger.info(f"✅ Token type: {token_type}")
        logger.info(f"✅ Databricks Endpoint: {workspace_url}/oidc/v1/token")
        if token_type == 'access_token':
            logger.info(f"✅ CORRECT: Using access_token (has proper audience)")
        else:
            logger.warning(f"⚠️  WARNING: Using id_token (may have wrong audience)")
        logger.info("=" * 80)
        
        databricks_response = exchange_for_databricks_token(token_for_exchange, workspace_url)
        
        # Store Databricks token
        session['workspace_token'] = databricks_response['access_token']
        session['token_obtained'] = datetime.now().isoformat()
        
        # Clear temporary session data and Entra tokens (to reduce session size)
        # We only need the Databricks workspace token now
        session.pop('oauth_state', None)
        session.pop('entra_access_token', None)  # Don't need this anymore
        
        logger.info("✅ Session optimized: Removed Entra access token (keeping only Databricks token)")
        
        logger.info("=" * 80)
        logger.info("✅ SUCCESS! COMPLETE OAUTH FLOW (MSAL)")
        logger.info("=" * 80)
        logger.info("✅ Step 1: Got token from ENTRA ID using MSAL")
        logger.info("✅ Step 2: Exchanged Entra ID token for Databricks token")
        logger.info("✅ You now have a valid Databricks workspace token")
        logger.info("✅ MSAL benefits: Automatic PKCE, token caching, refresh handling")
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
        'library': 'MSAL for Python',
        'config': {
            'tenant_id': config.tenant_id,
            'client_id': config.client_id,
            'redirect_uri': config.redirect_uri,
            'port': config.port,
            'client_type': 'public' if config.is_public_client else 'confidential',
            'authentication_flow': 'User-to-Machine (U2M)' if config.is_public_client else 'Confidential Client',
            'oauth_scope': config.scope,
            'msal_authority': config.authority
        }
    })

if __name__ == '__main__':
    logger.info(f"Starting Entra ID OAuth app (MSAL) on port {config.port}")
    logger.info(f"Redirect URI: {config.redirect_uri}")
    logger.info(f"Tenant ID: {config.tenant_id}")
    logger.info(f"Using MSAL Library: Simplified OAuth with automatic PKCE & token management")
    
    app.run(
        host='0.0.0.0',
        port=config.port,
        debug=True
    )

