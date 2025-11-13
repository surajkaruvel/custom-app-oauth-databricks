#!/usr/bin/env python3
"""
Service Principal OAuth App with Microsoft Entra ID (MSAL)

A Flask application that:
1. Authenticates using Service Principal (Client Credentials Flow) with MSAL
2. Exchanges Entra ID tokens for Databricks workspace tokens
3. Provides SQL Analytics and AI Assistant interfaces

This is a NON-INTERACTIVE flow - no user login required!
Uses MSAL for Python with Client Credentials grant type.
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

# Load environment variables (override=True ensures config.env values take precedence)
load_dotenv('config.env', override=True)

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
    PERMANENT_SESSION_LIFETIME=timedelta(hours=24)  # SP tokens last longer
)

class Config:
    def __init__(self):
        # Service Principal Configuration
        self.tenant_id = os.environ.get('SP_TENANT_ID', '')
        self.client_id = os.environ.get('SP_CLIENT_ID', '')
        self.client_secret = os.environ.get('SP_CLIENT_SECRET', '')  # Required for SP
        
        # Databricks Service Principal ID (can be different from SP_CLIENT_ID)
        # This is sent to Databricks token exchange endpoint
        self.databricks_sp_client_id = os.environ.get('DATABRICKS_SP_CLIENT_ID', self.client_id)
        
        # Entra ID authority
        self.authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        
        # OAuth scope for SP (uses /.default)
        self.scope = f"api://{self.client_id}/.default"
        self.scopes = [self.scope]
        
        # App configuration
        self.port = int(os.environ.get('PORT', 9001))

config = Config()

# Log configuration on startup
logger.info("=" * 80)
logger.info("📋 CONFIGURATION LOADED")
logger.info("=" * 80)
logger.info(f"SP Client ID (Entra): {config.client_id}")
logger.info(f"Databricks SP Client ID: {config.databricks_sp_client_id}")
logger.info(f"Port: {config.port}")
logger.info("=" * 80)

def get_sp_msal_app():
    """
    Create and return a Service Principal MSAL application instance.
    Uses ConfidentialClientApplication for client credentials flow.
    """
    logger.info("Creating MSAL ConfidentialClientApplication for Service Principal")
    return msal.ConfidentialClientApplication(
        client_id=config.client_id,
        client_credential=config.client_secret,
        authority=config.authority,
    )

def decode_jwt_payload(token):
    """Decode JWT payload without verification (for analysis only)"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None, "Invalid JWT format"
        
        header_data = parts[0] + '=' * (4 - len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_data))
        
        payload_data = parts[1] + '=' * (4 - len(parts[1]) % 4)
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
    logger.info(f"📋 {token_type.upper()} TOKEN ANALYSIS (SERVICE PRINCIPAL)")
    logger.info("=" * 80)
    
    # Log payload
    payload = decoded['payload']
    logger.info(f"\n🔑 KEY CLAIMS:")
    logger.info(f"  ✓ Issuer (iss): {payload.get('iss')}")
    logger.info(f"  ✓ Audience (aud): {payload.get('aud')}")
    logger.info(f"  ✓ Subject (sub): {payload.get('sub')}")
    logger.info(f"  ✓ App ID (appid): {payload.get('appid')}")
    logger.info(f"  ✓ Object ID (oid): {payload.get('oid')}")
    logger.info(f"  ✓ Tenant ID (tid): {payload.get('tid')}")
    logger.info(f"  ✓ Identity Provider (idp): {payload.get('idp')}")
    logger.info(f"  ✓ Issued At: {datetime.fromtimestamp(payload.get('iat', 0))}")
    logger.info(f"  ✓ Expires At: {datetime.fromtimestamp(payload.get('exp', 0))}")
    logger.info("=" * 80)

def exchange_for_databricks_token(sp_token, workspace_url):
    """Exchange Service Principal token for Databricks workspace token"""
    logger.info("Starting Databricks token exchange (Service Principal)")
    logger.info(f"Workspace URL: {workspace_url}")
    
    # For Service Principal authentication, Databricks requires client_id parameter
    # Use DATABRICKS_SP_CLIENT_ID which can be different from the Entra SP_CLIENT_ID
    databricks_data = {
        'subject_token': sp_token,
        'subject_token_type': 'urn:ietf:params:oauth:token-type:jwt',
        'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
        'scope': 'all-apis',
        'client_id': config.databricks_sp_client_id  # Databricks SP client ID
    }
    
    logger.info(f"Databricks token exchange request data: {dict(databricks_data)}")
    
    try:
        token_url = f"{workspace_url}/oidc/v1/token"
        logger.info(f"Databricks token endpoint: {token_url}")
        logger.info(f"Including client_id: {config.databricks_sp_client_id} (Databricks SP ID)")
        
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
        
        logger.info("Databricks token exchange successful (Service Principal)")
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
    """Main page - SP authentication interface"""
    if 'workspace_token' in session:
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
    authenticated_at = session.get('token_obtained')
    
    # Calculate remaining token validity
    expires_at_str = session.get('expires_at')
    if expires_at_str:
        expires_at = datetime.fromisoformat(expires_at_str)
        expires_in = max(0, int((expires_at - datetime.now()).total_seconds()))
    else:
        # Default if not stored (shouldn't happen with new code)
        expires_at = datetime.now() + timedelta(hours=1)
        expires_in = 3600
    
    return render_template('databricks_interface.html',
                         workspace_token=workspace_token,
                         workspace_url=workspace_url,
                         authenticated_at=authenticated_at,
                         auth_type='Service Principal',
                         expires_at=expires_at,
                         expires_in=expires_in)

@app.route('/authenticate', methods=['POST'])
def authenticate():
    """Authenticate using Service Principal (Client Credentials Flow)"""
    try:
        # Get workspace URL from form
        workspace_url = request.form.get('workspace_url', '').strip()
        
        if not workspace_url:
            flash('Workspace URL is required', 'error')
            return redirect(url_for('index'))
        
        if not workspace_url.startswith(('http://', 'https://')):
            flash('Workspace URL must start with http:// or https://', 'error')
            return redirect(url_for('index'))
        
        workspace_url = workspace_url.rstrip('/')
        session['workspace_url'] = workspace_url
        
        logger.info("=" * 80)
        logger.info("🔐 STARTING SERVICE PRINCIPAL AUTHENTICATION (MSAL)")
        logger.info("=" * 80)
        logger.info(f"✅ Authority: {config.authority}")
        logger.info(f"✅ Client ID (SP): {config.client_id}")
        logger.info(f"✅ Scope: {config.scope}")
        logger.info(f"✅ Flow: Client Credentials (Non-Interactive)")
        logger.info("=" * 80)
        
        # Use MSAL Client Credentials Flow
        sp_app = get_sp_msal_app()
        
        # Acquire token for client (Service Principal)
        # This is NON-INTERACTIVE - no user login required!
        result = sp_app.acquire_token_for_client(scopes=config.scopes)
        
        if "error" in result:
            error_msg = result.get("error_description", result.get("error"))
            logger.error(f"MSAL SP authentication error: {error_msg}")
            flash(f'Service Principal authentication error: {error_msg}', 'error')
            return redirect(url_for('index'))
        
        if "access_token" not in result:
            logger.error("No access token in MSAL result")
            flash('Failed to obtain Service Principal token', 'error')
            return redirect(url_for('index'))
        
        logger.info("✅ MSAL Service Principal token acquired successfully")
        logger.info(f"Token type: {result.get('token_type', 'Bearer')}")
        logger.info(f"Expires in: {result.get('expires_in', 'unknown')} seconds")
        
        # Analyze the SP token
        logger.info("\n" + "=" * 80)
        logger.info("🔍 ANALYZING SERVICE PRINCIPAL TOKEN")
        logger.info("=" * 80)
        analyze_token(result['access_token'], 'access_token')
        
        # Exchange SP token for Databricks token
        logger.info("\n" + "=" * 80)
        logger.info("🔄 EXCHANGING SP TOKEN FOR DATABRICKS TOKEN")
        logger.info("=" * 80)
        logger.info(f"✅ Using Service Principal access token")
        logger.info(f"✅ Databricks Endpoint: {workspace_url}/oidc/v1/token")
        logger.info("=" * 80)
        
        databricks_response = exchange_for_databricks_token(
            result['access_token'], 
            workspace_url
        )
        
        # Store Databricks token and expiry information
        session['workspace_token'] = databricks_response['access_token']
        session['token_obtained'] = datetime.now().isoformat()
        session['auth_type'] = 'Service Principal'
        
        # Calculate token expiry (default to 3600 seconds if not provided)
        expires_in_seconds = databricks_response.get('expires_in', 3600)
        expires_at = datetime.now() + timedelta(seconds=expires_in_seconds)
        session['expires_at'] = expires_at.isoformat()
        session['expires_in'] = expires_in_seconds
        
        logger.info("=" * 80)
        logger.info("✅ SUCCESS! COMPLETE SERVICE PRINCIPAL AUTHENTICATION")
        logger.info("=" * 80)
        logger.info("✅ Step 1: Got token from ENTRA ID using MSAL (Client Credentials)")
        logger.info("✅ Step 2: Exchanged SP token for Databricks token")
        logger.info("✅ You now have a valid Databricks workspace token")
        logger.info("✅ Authentication Type: Service Principal (Non-Interactive)")
        logger.info("=" * 80)
        
        flash('Service Principal authentication successful!', 'success')
        return redirect(url_for('databricks_interface'))
        
    except Exception as e:
        logger.error(f"Error during SP authentication: {str(e)}")
        flash(f'Error during authentication: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/sql-setup')
def sql_setup():
    """SQL interface setup page"""
    if 'workspace_token' not in session:
        flash('Please complete authentication first.', 'error')
        return redirect(url_for('index'))
    
    workspace_url = session.get('workspace_url')
    
    # Calculate remaining token validity
    expires_at_str = session.get('expires_at')
    if expires_at_str:
        expires_at = datetime.fromisoformat(expires_at_str)
        expires_in = max(0, int((expires_at - datetime.now()).total_seconds()))
    else:
        expires_at = datetime.now() + timedelta(hours=1)
        expires_in = 3600
    
    return render_template('sql_setup.html', 
                         workspace_url=workspace_url,
                         expires_at=expires_at,
                         expires_in=expires_in)

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
    
    # Calculate remaining token validity
    expires_at_str = session.get('expires_at')
    if expires_at_str:
        expires_at = datetime.fromisoformat(expires_at_str)
        expires_in = max(0, int((expires_at - datetime.now()).total_seconds()))
    else:
        expires_at = datetime.now() + timedelta(hours=1)
        expires_in = 3600
    
    return render_template('sql_interface.html',
                         workspace_token=workspace_token,
                         workspace_url=workspace_url,
                         warehouse_id=warehouse_id,
                         auth_type='Service Principal',
                         expires_at=expires_at,
                         expires_in=expires_in)

@app.route('/chat-setup')
def chat_setup():
    """Chat interface setup page"""
    if 'workspace_token' not in session:
        flash('Please complete authentication first.', 'error')
        return redirect(url_for('index'))
    
    workspace_url = session.get('workspace_url')
    
    # Calculate remaining token validity
    expires_at_str = session.get('expires_at')
    if expires_at_str:
        expires_at = datetime.fromisoformat(expires_at_str)
        expires_in = max(0, int((expires_at - datetime.now()).total_seconds()))
    else:
        expires_at = datetime.now() + timedelta(hours=1)
        expires_in = 3600
    
    return render_template('chat_setup.html', 
                         workspace_url=workspace_url,
                         expires_at=expires_at,
                         expires_in=expires_in)

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
    
    # Calculate remaining token validity
    expires_at_str = session.get('expires_at')
    if expires_at_str:
        expires_at = datetime.fromisoformat(expires_at_str)
        expires_in = max(0, int((expires_at - datetime.now()).total_seconds()))
    else:
        expires_at = datetime.now() + timedelta(hours=1)
        expires_in = 3600
    
    return render_template('chat_interface.html',
                         workspace_token=workspace_token,
                         workspace_url=workspace_url,
                         model_endpoint=model_endpoint,
                         auth_type='Service Principal',
                         expires_at=expires_at,
                         expires_in=expires_in)

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
        'auth_type': 'Service Principal (Client Credentials)',
        'config': {
            'tenant_id': config.tenant_id,
            'client_id': config.client_id,
            'databricks_sp_client_id': config.databricks_sp_client_id,
            'port': config.port,
            'flow': 'Client Credentials (Non-Interactive)',
            'oauth_scope': config.scope,
            'msal_authority': config.authority
        }
    })

if __name__ == '__main__':
    logger.info(f"Starting Service Principal OAuth app (MSAL) on port {config.port}")
    logger.info(f"Tenant ID: {config.tenant_id}")
    logger.info(f"Client ID: {config.client_id}")
    logger.info(f"Using MSAL Library: Client Credentials Flow (Non-Interactive)")
    logger.info(f"Authentication: Service Principal - NO USER INTERACTION REQUIRED")
    
    app.run(
        host='0.0.0.0',
        port=config.port,
        debug=True
    )

