#!/usr/bin/env python3
"""
Databricks SQL Interface - Service Principal (M2M) Application

This application uses Okta Service Application (API Services type) for machine-to-machine authentication.
No user authentication required - uses OAuth Client Credentials flow.

Features:
- Service Principal authentication (M2M)
- OAuth Client Credentials flow with Okta
- Automatic token refresh
- Databricks SQL endpoint integration
- No user interaction required
"""

import os
import logging
import requests
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify
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
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'service-principal-oauth-app-secret')

class Config:
    """Configuration class for the service principal app"""
    def __init__(self):
        # Okta Service Application Configuration
        self.issuer_url = os.environ.get('ISSUER_URL', '')
        self.client_id = os.environ.get('CLIENT_ID', '')
        self.client_secret = os.environ.get('CLIENT_SECRET', '')
        self.oauth_scope = os.environ.get('OAUTH_SCOPE', 'databricks-token-federation')
        
        # Databricks Configuration
        self.databricks_server_hostname = os.environ.get('DATABRICKS_SERVER_HOSTNAME', '')
        self.databricks_http_path = os.environ.get('DATABRICKS_HTTP_PATH', '')
        self.sp_uuid = os.environ.get('SP_UUID', '')
        
        # Model Serving Configuration
        self.model_serving_endpoint = os.environ.get('MODEL_SERVING_ENDPOINT', '')
        self.model_name = os.environ.get('MODEL_NAME', 'databricks-gpt-oss-20b')
        self.model_max_tokens = int(os.environ.get('MODEL_MAX_TOKENS', '256'))
        
        # App Configuration
        self.port = int(os.environ.get('PORT', 7000))
        self.debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
        
        # Validate required configuration
        self.validate()
    
    def validate(self):
        """Validate required configuration"""
        if not self.issuer_url:
            logger.warning("Okta issuer URL not configured")
        if not self.client_id:
            logger.warning("Okta client ID not configured")
        if not self.client_secret:
            logger.warning("Okta client secret not configured")
        if not self.databricks_server_hostname:
            logger.warning("Databricks server hostname not configured")

# Global configuration
config = Config()

# Token storage (in-memory for this demo)
token_cache = {
    'access_token': None,
    'workspace_token': None,
    'token_obtained': None,
    'expires_at': None
}

def get_service_principal_token():
    """Get access token using OAuth Client Credentials flow with client secret"""
    try:
        logger.info("Getting service principal token from Okta using Client Credentials flow with client secret")
        
        token_data = {
            'grant_type': 'client_credentials',
            'client_id': config.client_id,
            'client_secret': config.client_secret,
            'scope': config.oauth_scope
        }
        
        response = requests.post(
            f"{config.issuer_url}/v1/token",
            data=token_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=30
        )
        response.raise_for_status()
        token_response = response.json()
        
        logger.info("Service principal token obtained successfully with client secret")
        return token_response
        
    except requests.RequestException as e:
        logger.error(f"Service principal token request failed: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_details = e.response.json()
                logger.error(f"Error details: {error_details}")
            except:
                logger.error(f"Response text: {e.response.text}")
        raise

def exchange_for_workspace_token(access_token):
    """Exchange Okta access token for Databricks workspace token"""
    try:
        logger.info("Exchanging service principal token for Databricks workspace token")
        
        workspace_url = f"https://{config.databricks_server_hostname}"
        token_exchange_url = f"{workspace_url}/oidc/v1/token"
        
        exchange_data = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
            'subject_token': access_token,
            'subject_token_type': 'urn:ietf:params:oauth:token-type:access_token',
            'scope': 'all-apis'
        }
        
        # Add client_id if SP_UUID is configured
        if config.sp_uuid:
            exchange_data['client_id'] = config.sp_uuid
            logger.info(f"Using SP_UUID as client_id for token exchange: {config.sp_uuid}")
        
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        
        response = requests.post(
            token_exchange_url,
            data=exchange_data,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()
        workspace_response = response.json()
        
        logger.info("Workspace token obtained successfully")
        return workspace_response
        
    except requests.RequestException as e:
        logger.error(f"Workspace token exchange failed: {str(e)}")
        raise

def refresh_tokens():
    """Refresh both Okta and Databricks tokens"""
    try:
        # Get new Okta service principal token
        okta_response = get_service_principal_token()
        access_token = okta_response.get('access_token')
        
        # Exchange for new workspace token
        workspace_response = exchange_for_workspace_token(access_token)
        workspace_token = workspace_response.get('access_token')
        
        # Update token cache
        now = datetime.now()
        token_cache.update({
            'access_token': access_token,
            'workspace_token': workspace_token,
            'token_obtained': now.isoformat(),
            'expires_at': (now + timedelta(seconds=3600)).isoformat()  # 1 hour expiration
        })
        
        logger.info("All tokens refreshed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Token refresh failed: {str(e)}")
        return False

def is_token_expired():
    """Check if tokens are expired or will expire soon (5 minute buffer)"""
    if not token_cache.get('token_obtained'):
        return True
    
    try:
        token_obtained = datetime.fromisoformat(token_cache['token_obtained'])
        # Check if token is older than 55 minutes (5 minute buffer before 1 hour expiration)
        time_elapsed = datetime.now() - token_obtained
        return time_elapsed > timedelta(minutes=55)
    except Exception:
        return True

def ensure_valid_tokens():
    """Ensure we have valid tokens, refresh if needed"""
    if is_token_expired():
        logger.info("Tokens expired or missing, refreshing...")
        return refresh_tokens()
    return True

def execute_sql_query(query, warehouse_id):
    """Execute SQL query on Databricks SQL endpoint"""
    try:
        # Ensure we have valid tokens
        if not ensure_valid_tokens():
            raise Exception("Failed to obtain valid tokens")
        
        workspace_token = token_cache.get('workspace_token')
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

# Routes
@app.route('/')
def index():
    """Main page - redirect to dashboard"""
    logger.info("Serving service principal app index page")
    return render_template('dashboard.html',
                         server_hostname=config.databricks_server_hostname,
                         model_name=config.model_name,
                         workspace_url=f"https://{config.databricks_server_hostname}",
                         client_id=config.client_id[:12] + '...' if config.client_id else 'Not configured')

@app.route('/dashboard')
def dashboard():
    """Dashboard page"""
    logger.info("Serving service principal dashboard")
    return render_template('dashboard.html',
                         server_hostname=config.databricks_server_hostname,
                         model_name=config.model_name,
                         workspace_url=f"https://{config.databricks_server_hostname}",
                         client_id=config.client_id[:12] + '...' if config.client_id else 'Not configured')

@app.route('/sql')
def sql_interface():
    """SQL query interface"""
    logger.info("Serving SQL interface")
    
    # Ensure we have valid tokens
    if not ensure_valid_tokens():
        return jsonify({'error': 'Failed to authenticate service principal'}), 500
    
    # Get default warehouse ID if configured
    default_warehouse_id = ''
    if config.databricks_http_path and '/warehouses/' in config.databricks_http_path:
        default_warehouse_id = config.databricks_http_path.split('/warehouses/')[-1]
    
    return render_template('sql_interface.html',
                         server_hostname=config.databricks_server_hostname,
                         default_warehouse_id=default_warehouse_id,
                         token_obtained=token_cache.get('token_obtained'),
                         expires_at=token_cache.get('expires_at'))

@app.route('/execute-sql', methods=['POST'])
def execute_sql():
    """Execute SQL query"""
    try:
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
            'warehouse_id': warehouse_id,
            'executed_as': 'Service Principal'
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
        # Ensure we have valid tokens
        if not ensure_valid_tokens():
            raise Exception("Failed to obtain valid tokens")
        
        workspace_token = token_cache.get('workspace_token')
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
            client = OpenAI(
                api_key=workspace_token,
                base_url=base_url,
                timeout=30.0,
                max_retries=2
            )
        except Exception as client_error:
            logger.error(f"Failed to create OpenAI client: {str(client_error)}")
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
    workspace_url = f"https://{config.databricks_server_hostname}"
    
    return render_template('chat_interface.html',
                         workspace_url=workspace_url,
                         model_name=config.model_name,
                         server_hostname=config.databricks_server_hostname,
                         client_id=config.client_id[:12] + '...' if config.client_id else 'Not configured')

@app.route('/send-message', methods=['POST'])
def send_message():
    """Send message to the model and get response"""
    try:
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
            'max_tokens': max_tokens,
            'executed_as': 'Service Principal'
        })
        
    except Exception as e:
        logger.error(f"Chat message error: {str(e)}")
        return jsonify({
            'success': False,
            'error': f"Chat failed: {str(e)}"
        }), 500

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

@app.route('/health')
def health():
    """Health check endpoint"""
    try:
        # Check if we can get tokens
        tokens_valid = ensure_valid_tokens()
        
        return jsonify({
            'status': 'healthy' if tokens_valid else 'degraded',
            'service_principal_configured': bool(config.client_id and config.client_secret),
            'okta_configured': bool(config.issuer_url),
            'databricks_configured': bool(config.databricks_server_hostname),
            'tokens_valid': tokens_valid,
            'token_obtained': token_cache.get('token_obtained'),
            'app_type': 'Service Principal (M2M)',
            'authentication_flow': 'OAuth Client Credentials'
        })
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500

@app.route('/token-status')
def token_status():
    """Get current token status"""
    if not token_cache.get('token_obtained'):
        return jsonify({'error': 'No tokens available'}), 400
    
    try:
        token_obtained = datetime.fromisoformat(token_cache['token_obtained'])
        time_elapsed = datetime.now() - token_obtained
        time_remaining = timedelta(hours=1) - time_elapsed
        
        return jsonify({
            'token_obtained': token_cache['token_obtained'],
            'time_elapsed_minutes': int(time_elapsed.total_seconds() / 60),
            'time_remaining_minutes': int(time_remaining.total_seconds() / 60),
            'expires_soon': is_token_expired(),
            'authentication_type': 'Service Principal',
            'flow_type': 'Client Credentials'
        })
    except Exception as e:
        return jsonify({'error': f'Error calculating token status: {str(e)}'}), 500

@app.route('/refresh-tokens', methods=['POST'])
def refresh_tokens_endpoint():
    """Manually refresh tokens"""
    try:
        success = refresh_tokens()
        if success:
            return jsonify({
                'success': True,
                'message': 'Tokens refreshed successfully',
                'token_obtained': token_cache.get('token_obtained')
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Token refresh failed'
            }), 500
    except Exception as e:
        logger.error(f"Manual token refresh failed: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

if __name__ == '__main__':
    # Validate configuration
    if not config.client_id or not config.client_secret:
        logger.error("❌ Missing required Okta Service Application credentials")
        logger.error("   Please configure CLIENT_ID and CLIENT_SECRET in config.env")
        exit(1)
    
    if not config.issuer_url:
        logger.error("❌ Missing Okta issuer URL")
        logger.error("   Please configure ISSUER_URL in config.env")
        exit(1)
    
    if not config.databricks_server_hostname:
        logger.error("❌ Missing Databricks server hostname")
        logger.error("   Please configure DATABRICKS_SERVER_HOSTNAME in config.env")
        exit(1)
    
    # Initialize tokens on startup
    logger.info("🚀 Starting Service Principal OAuth App")
    logger.info(f"   Port: {config.port}")
    logger.info(f"   Client ID: {config.client_id[:12]}...")
    logger.info(f"   Databricks Server: {config.databricks_server_hostname}")
    logger.info("🔄 Using OAuth Client Credentials Flow (M2M)")
    
    # Get initial tokens
    if ensure_valid_tokens():
        logger.info("✅ Initial token acquisition successful")
    else:
        logger.warning("⚠️  Initial token acquisition failed - will retry on first request")
    
    app.run(host='0.0.0.0', port=config.port, debug=config.debug)
