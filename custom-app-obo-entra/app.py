"""
Databricks OAuth with Microsoft Entra ID - On-Behalf-Of (OBO) Flow
Demonstrates middle-tier service exchanging user token for Databricks access

Architecture:
1. User → Middle-Tier: Auth code flow with PKCE
2. Middle-Tier → Entra ID: OBO exchange for Databricks token
3. Middle-Tier → Databricks: Direct API calls with OBO token

No Databricks /oidc/v1/token exchange needed - OBO token works directly!
"""

import os
import logging
import secrets
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import requests
import msal
from dotenv import load_dotenv

# Load environment variables
load_dotenv('config.env', override=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

# Session configuration
app.config.update(
    SESSION_COOKIE_SECURE=False,  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB max request size
    MAX_COOKIE_SIZE=4093  # Browser cookie size limit
)

# Note: For production, consider using server-side session storage
# (e.g., Flask-Session with Redis) to avoid cookie size limitations


class Config:
    """Application configuration from environment variables"""
    
    def __init__(self):
        # Middle-Tier App Configuration (API1)
        self.tenant_id = os.environ.get('MIDDLETIER_TENANT_ID', '')
        self.client_id = os.environ.get('MIDDLETIER_CLIENT_ID', '')
        self.client_secret = os.environ.get('MIDDLETIER_CLIENT_SECRET', '')
        
        # Databricks Scope (API2)
        self.databricks_scope = os.environ.get('DATABRICKS_SCOPE', '')
        
        # Snowflake Scope (API4)
        self.snowflake_scope = os.environ.get('SNOWFLAKE_SCOPE', '')
        
        # Entra ID authority
        self.authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        
        # OAuth scopes for middle-tier
        # Note: MSAL automatically adds 'openid' and 'profile' - don't include them
        self.scope = f"api://{self.client_id}/access_as_user"
        self.scopes = [self.scope]
        
        # App configuration
        self.port = int(os.environ.get('PORT', 9001))
        self.redirect_uri = os.environ.get('REDIRECT_URI', f'http://localhost:{self.port}/callback')
        
        logger.info("=" * 80)
        logger.info("🔧 CONFIGURATION LOADED (OBO Flow)")
        logger.info("=" * 80)
        logger.info(f"Middle-Tier Client ID: {self.client_id}")
        logger.info(f"Databricks Scope: {self.databricks_scope}")
        logger.info(f"Snowflake Scope: {self.snowflake_scope}")
        logger.info(f"Redirect URI: {self.redirect_uri}")
        logger.info(f"Port: {self.port}")
        logger.info("=" * 80)


config = Config()


def create_msal_app():
    """Create MSAL Confidential Client Application"""
    return msal.ConfidentialClientApplication(
        config.client_id,
        authority=config.authority,
        client_credential=config.client_secret
    )


def exchange_for_databricks_token(middle_tier_token):
    """
    Exchange middle-tier token for Databricks token using OBO flow
    
    This token works DIRECTLY with Databricks APIs - no /oidc/v1/token needed!
    """
    logger.info("\n" + "=" * 80)
    logger.info("🔄 ON-BEHALF-OF (OBO) TOKEN EXCHANGE - DATABRICKS")
    logger.info("=" * 80)
    logger.info(f"Exchanging middle-tier token for Databricks access")
    logger.info(f"Target scope: {config.databricks_scope}")
    
    msal_app = create_msal_app()
    
    try:
        # OBO token exchange
        result = msal_app.acquire_token_on_behalf_of(
            user_assertion=middle_tier_token,
            scopes=[config.databricks_scope]
        )
        
        if 'access_token' in result:
            logger.info("✅ OBO token exchange successful!")
            logger.info(f"✅ Token expires in: {result.get('expires_in', 'unknown')} seconds")
            logger.info("✅ This token works DIRECTLY with Databricks APIs")
            logger.info("=" * 80)
            return result
        else:
            error_msg = result.get('error_description', result.get('error', 'Unknown error'))
            logger.error(f"❌ OBO token exchange failed: {error_msg}")
            raise Exception(f"OBO exchange failed: {error_msg}")
            
    except Exception as e:
        logger.error(f"❌ Error during OBO exchange: {str(e)}")
        raise


def exchange_for_snowflake_token(middle_tier_token):
    """
    Exchange middle-tier token for Snowflake token using OBO flow
    
    This token works DIRECTLY with Snowflake APIs!
    """
    import json
    import base64
    
    logger.info("\n" + "=" * 80)
    logger.info("🔄 ON-BEHALF-OF (OBO) TOKEN EXCHANGE - SNOWFLAKE")
    logger.info("=" * 80)
    logger.info(f"Exchanging middle-tier token for Snowflake access")
    logger.info(f"Target scope: {config.snowflake_scope}")
    
    msal_app = create_msal_app()
    
    try:
        # OBO token exchange
        result = msal_app.acquire_token_on_behalf_of(
            user_assertion=middle_tier_token,
            scopes=[config.snowflake_scope]
        )
        
        if 'access_token' in result:
            logger.info("✅ OBO token exchange successful!")
            logger.info(f"✅ Token expires in: {result.get('expires_in', 'unknown')} seconds")
            
            # Decode and inspect token (for debugging)
            try:
                token = result['access_token']
                # JWT has 3 parts: header.payload.signature
                parts = token.split('.')
                if len(parts) >= 2:
                    # Decode payload (add padding if needed)
                    payload = parts[1]
                    payload += '=' * (4 - len(payload) % 4)  # Add padding
                    decoded = json.loads(base64.b64decode(payload))
                    
                    logger.info(f"📋 Token Claims:")
                    logger.info(f"   - Audience (aud): {decoded.get('aud', 'N/A')}")
                    logger.info(f"   - Issuer (iss): {decoded.get('iss', 'N/A')}")
                    logger.info(f"   - Subject (sub): {decoded.get('sub', 'N/A')}")
                    
                    scopes = decoded.get('scp', 'N/A')
                    logger.info(f"   - Scopes (scp): {scopes}")
                    
                    # Check if role is embedded in scope
                    # Format: session:scope:ACCOUNTADMIN or just ACCOUNTADMIN
                    scope_str = str(scopes)
                    if 'session:scope:' in scope_str:
                        role_match = scope_str.split('session:scope:')
                        if len(role_match) > 1:
                            role_name = role_match[1].split()[0]  # Get first word after session:scope:
                            logger.info(f"   🎭 Role embedded in token: {role_name}")
                            logger.info(f"   ✅ Token will automatically assume {role_name} role in Snowflake")
                    elif any(role in scope_str for role in ['ACCOUNTADMIN', 'SYSADMIN', 'PUBLIC', 'SECURITYADMIN']):
                        # Fallback: direct role name
                        for role in ['ACCOUNTADMIN', 'SYSADMIN', 'PUBLIC', 'SECURITYADMIN']:
                            if role in scope_str:
                                logger.info(f"   🎭 Role embedded in token: {role}")
                                logger.info(f"   ✅ Token will automatically assume {role} role in Snowflake")
                                break
                    
                    # Check if audience matches Snowflake client ID from config
                    expected_aud = config.snowflake_scope.split('/')[2] if '/' in config.snowflake_scope else ''
                    actual_aud = decoded.get('aud', '')
                    if expected_aud and (expected_aud in actual_aud or actual_aud in expected_aud):
                        logger.info(f"   ✅ Audience matches Snowflake app")
                    elif expected_aud:
                        logger.warning(f"   ⚠️  Audience mismatch detected")
            except Exception as decode_err:
                logger.warning(f"Could not decode token for inspection: {decode_err}")
            
            logger.info("✅ This token works DIRECTLY with Snowflake APIs")
            logger.info("=" * 80 + "\n")
            return result
        else:
            error_msg = result.get('error_description', result.get('error', 'Unknown error'))
            logger.error(f"❌ OBO token exchange failed: {error_msg}")
            raise Exception(f"OBO exchange failed: {error_msg}")
            
    except Exception as e:
        logger.error(f"❌ Error during OBO exchange: {str(e)}")
        raise


@app.route('/')
def index():
    """Home page - Initial login screen"""
    # Check if user has middle-tier token
    middle_tier_token = session.get('middle_tier_token')
    user_email = session.get('user_email')
    
    if middle_tier_token:
        # User is authenticated with middle-tier
        return redirect(url_for('dashboard'))
    
    return render_template('index.html',
                         authenticated=False,
                         auth_type='OBO Flow')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Initiate OAuth login with middle-tier app"""
    # Generate state for CSRF protection
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    
    # Build MSAL auth request for middle-tier authentication only
    # Note: For confidential clients, MSAL handles PKCE internally
    msal_app = create_msal_app()
    auth_url = msal_app.get_authorization_request_url(
        scopes=config.scopes,
        state=state,
        redirect_uri=config.redirect_uri
    )
    
    logger.info("\n" + "=" * 80)
    logger.info("🔐 STEP 1: USER AUTHENTICATION (Middle-Tier)")
    logger.info("=" * 80)
    logger.info(f"Redirecting to Entra ID for authentication")
    logger.info(f"Scopes: {config.scopes}")
    logger.info(f"Auth Type: Confidential Client (with client secret)")
    logger.info("=" * 80)
    
    return redirect(auth_url)


@app.route('/callback')
def oauth_callback():
    """Handle OAuth callback from Entra ID"""
    # Verify state
    state = request.args.get('state')
    if state != session.get('oauth_state'):
        flash('Invalid state parameter', 'error')
        return redirect(url_for('index'))
    
    # Get authorization code
    auth_code = request.args.get('code')
    error = request.args.get('error')
    
    if error:
        flash(f'OAuth error: {error}', 'error')
        return redirect(url_for('index'))
    
    if not auth_code:
        flash('No authorization code received', 'error')
        return redirect(url_for('index'))
    
    logger.info("\n" + "=" * 80)
    logger.info("🎟️  STEP 2: EXCHANGE AUTH CODE FOR MIDDLE-TIER TOKEN")
    logger.info("=" * 80)
    
    try:
        # Exchange auth code for middle-tier token
        msal_app = create_msal_app()
        result = msal_app.acquire_token_by_authorization_code(
            code=auth_code,
            scopes=config.scopes,
            redirect_uri=config.redirect_uri
        )
        
        if 'access_token' not in result:
            error_msg = result.get('error_description', result.get('error', 'Unknown error'))
            logger.error(f"❌ Token acquisition failed: {error_msg}")
            flash(f'Token acquisition failed: {error_msg}', 'error')
            return redirect(url_for('index'))
        
        logger.info("✅ Middle-tier token acquired successfully")
        
        # Store middle-tier token and user info
        # Note: middle_tier_token will be removed after OBO exchange to reduce session size
        session['middle_tier_token'] = result['access_token']
        session['user_email'] = result.get('id_token_claims', {}).get('preferred_username', 'Unknown')
        session['authenticated_at'] = datetime.now().isoformat()
        
        # Clear temporary session data
        session.pop('oauth_state', None)
        
        logger.info("✅ Middle-tier authentication complete!")
        logger.info(f"✅ User: {session.get('user_email')}")
        logger.info("=" * 80)
        
        flash('Successfully authenticated with middle-tier service!', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        logger.error(f"❌ Error during OAuth callback: {str(e)}")
        flash(f'Authentication error: {str(e)}', 'error')
        return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    """Dashboard - shows authenticated status and allows Databricks access"""
    # Check if user is authenticated (either has middle_tier_token or databricks_token)
    middle_tier_token = session.get('middle_tier_token')
    databricks_token = session.get('databricks_token')
    
    if not middle_tier_token and not databricks_token:
        flash('Please authenticate first.', 'error')
        return redirect(url_for('index'))
    
    user_email = session.get('user_email')
    authenticated_at = session.get('authenticated_at')
    workspace_url = session.get('workspace_url')
    warehouse_id = session.get('warehouse_id')
    snowflake_token = session.get('snowflake_token')
    
    return render_template('dashboard.html',
                         user_email=user_email,
                         authenticated_at=authenticated_at,
                         has_databricks_token=databricks_token is not None,
                         has_snowflake_token=snowflake_token is not None,
                         workspace_url=workspace_url,
                         warehouse_id=warehouse_id,
                         auth_type='OBO Flow')




@app.route('/sql-setup', methods=['GET', 'POST'])
def sql_setup():
    """SQL interface setup page - collects workspace URL and warehouse ID, performs OBO exchange"""
    
    if request.method == 'POST':
        # User submitted the form with workspace URL and warehouse ID
        workspace_url = request.form.get('workspace_url')
        warehouse_id = request.form.get('warehouse_id')
        
        if not workspace_url or not warehouse_id:
            flash('Please provide both workspace URL and warehouse ID', 'error')
            return render_template('sql_setup.html')
        
        # Check if we need to do OBO exchange
        databricks_token = session.get('databricks_token')
        middle_tier_token = session.get('middle_tier_token')
        
        if not databricks_token:
            # Need middle_tier_token for OBO exchange
            if not middle_tier_token:
                flash('Session expired. Please authenticate again.', 'error')
                return redirect(url_for('index'))
            
            try:
                # STEP 3: OBO Exchange for Databricks token
                logger.info("\n" + "=" * 80)
                logger.info("🔄 STEP 3: OBO EXCHANGE FOR DATABRICKS TOKEN")
                logger.info("=" * 80)
                logger.info(f"Triggered by: Databricks SQL Interface access")
                logger.info(f"Workspace URL: {workspace_url}")
                logger.info(f"Warehouse ID: {warehouse_id}")
                
                databricks_result = exchange_for_databricks_token(middle_tier_token)
                
                # Store Databricks token and configuration
                session['databricks_token'] = databricks_result['access_token']
                session['workspace_url'] = workspace_url
                session['warehouse_id'] = warehouse_id
                session['token_obtained'] = datetime.now().isoformat()
                
                # Calculate expiration
                expires_in = databricks_result.get('expires_in', 3600)
                expires_at = datetime.now() + timedelta(seconds=expires_in)
                session['expires_at'] = expires_at.isoformat()
                session['expires_in'] = expires_in
                
                # Clear middle-tier token to reduce session size
                session.pop('middle_tier_token', None)
                
                logger.info("✅ OBO token exchange complete!")
                logger.info("✅ Databricks token obtained")
                logger.info("✅ Session optimized: Removed middle-tier token")
                logger.info("=" * 80)
                
                flash('Databricks token obtained via OBO exchange!', 'success')
                
            except Exception as e:
                logger.error(f"❌ OBO exchange failed: {str(e)}")
                flash(f'OBO exchange failed: {str(e)}', 'error')
                return render_template('sql_setup.html')
        else:
            # Already have token, just update workspace URL and warehouse ID
            session['workspace_url'] = workspace_url
            session['warehouse_id'] = warehouse_id
        
        # Redirect to SQL interface with default catalog and schema
        return redirect(url_for('sql_interface', 
                               warehouse_id=warehouse_id,
                               catalog='hive_metastore',
                               schema='default'))
    
    # GET request - show the setup form
    middle_tier_token = session.get('middle_tier_token')
    databricks_token = session.get('databricks_token')
    
    if not middle_tier_token and not databricks_token:
        flash('Please authenticate first.', 'error')
        return redirect(url_for('index'))
    
    return render_template('sql_setup.html')


@app.route('/sql-interface')
def sql_interface():
    """SQL execution interface"""
    databricks_token = session.get('databricks_token')
    if not databricks_token:
        flash('No token found. Please complete authentication first.', 'error')
        return redirect(url_for('index'))
    
    warehouse_id = request.args.get('warehouse_id')
    catalog = request.args.get('catalog', 'hive_metastore')
    schema = request.args.get('schema', 'default')
    workspace_url = session.get('workspace_url')
    
    expires_at_str = session.get('expires_at')
    if expires_at_str:
        expires_at = datetime.fromisoformat(expires_at_str)
        expires_in = max(0, int((expires_at - datetime.now()).total_seconds()))
    else:
        expires_at = datetime.now() + timedelta(hours=1)
        expires_in = 3600
    
    return render_template('sql_interface.html',
                         warehouse_id=warehouse_id,
                         catalog=catalog,
                         schema=schema,
                         workspace_url=workspace_url,
                         expires_at=expires_at,
                         expires_in=expires_in)




@app.route('/api/execute-sql', methods=['POST'])
def execute_sql():
    """Execute SQL statement via Databricks SQL Execution API"""
    databricks_token = session.get('databricks_token')
    if not databricks_token:
        return jsonify({'error': 'No token found'}), 401
    
    data = request.json
    sql_statement = data.get('statement')
    warehouse_id = data.get('warehouse_id')
    catalog = data.get('catalog', 'hive_metastore')
    schema = data.get('schema', 'default')
    workspace_url = session.get('workspace_url')
    
    if not sql_statement or not warehouse_id:
        return jsonify({'error': 'Missing required parameters'}), 400
    
    try:
        # Use OBO token directly with Databricks API
        headers = {
            'Authorization': f'Bearer {databricks_token}',
            'Content-Type': 'application/json'
        }
        
        request_data = {
            'statement': sql_statement,
            'warehouse_id': warehouse_id,
            'catalog': catalog,
            'schema': schema,
            'wait_timeout': '30s'
        }
        
        logger.info(f"Executing SQL with OBO token: {sql_statement[:100]}...")
        
        response = requests.post(
            f"{workspace_url}/api/2.0/sql/statements",
            headers=headers,
            json=request_data,
            timeout=35
        )
        
        response.raise_for_status()
        return jsonify(response.json())
        
    except requests.exceptions.RequestException as e:
        logger.error(f"SQL execution error: {str(e)}")
        error_detail = e.response.json() if e.response else str(e)
        return jsonify({'error': str(e), 'detail': error_detail}), 500


@app.route('/snowflake-setup', methods=['GET', 'POST'])
def snowflake_setup():
    """Snowflake interface setup page - collects Snowflake connection details, performs OBO exchange"""
    
    if request.method == 'POST':
        # User submitted the form with Snowflake connection details
        account = request.form.get('account')
        database = request.form.get('database')
        schema = request.form.get('schema')
        warehouse = request.form.get('warehouse')
        role = request.form.get('role')
        
        if not account:
            flash('Please provide Snowflake account name', 'error')
            return render_template('snowflake_setup.html')
        
        # Check if we need to do OBO exchange
        snowflake_token = session.get('snowflake_token')
        middle_tier_token = session.get('middle_tier_token')
        
        if not snowflake_token:
            # Need middle_tier_token for OBO exchange
            if not middle_tier_token:
                flash('Session expired. Please authenticate again.', 'error')
                return redirect(url_for('index'))
            
            try:
                # STEP 3: OBO Exchange for Snowflake token
                logger.info("\n" + "=" * 80)
                logger.info("🔄 STEP 3: OBO EXCHANGE FOR SNOWFLAKE TOKEN")
                logger.info("=" * 80)
                logger.info(f"Triggered by: Snowflake SQL Interface access")
                logger.info(f"Snowflake Account: {account}")
                
                snowflake_result = exchange_for_snowflake_token(middle_tier_token)
                
                # Store Snowflake token and configuration
                session['snowflake_token'] = snowflake_result['access_token']
                session['snowflake_account'] = account
                session['snowflake_database'] = database or ''
                session['snowflake_schema'] = schema or ''
                session['snowflake_warehouse'] = warehouse or ''
                session['snowflake_role'] = role or ''
                session['snowflake_token_obtained'] = datetime.now().isoformat()
                
                # Calculate expiration
                expires_in = snowflake_result.get('expires_in', 3600)
                expires_at = datetime.now() + timedelta(seconds=expires_in)
                session['snowflake_expires_at'] = expires_at.isoformat()
                session['snowflake_expires_in'] = expires_in
                
                logger.info("✅ OBO token exchange complete!")
                logger.info("✅ Snowflake token obtained")
                logger.info("=" * 80)
                
                flash('Snowflake token obtained via OBO exchange!', 'success')
                
            except Exception as e:
                logger.error(f"❌ OBO exchange failed: {str(e)}")
                flash(f'OBO exchange failed: {str(e)}', 'error')
                return render_template('snowflake_setup.html')
        else:
            # Already have token, just update configuration
            session['snowflake_account'] = account
            session['snowflake_database'] = database or ''
            session['snowflake_schema'] = schema or ''
            session['snowflake_warehouse'] = warehouse or ''
            session['snowflake_role'] = role or ''
        
        # Redirect to Snowflake interface
        return redirect(url_for('snowflake_interface'))
    
    # GET request - show the setup form
    middle_tier_token = session.get('middle_tier_token')
    snowflake_token = session.get('snowflake_token')
    
    if not middle_tier_token and not snowflake_token:
        flash('Please authenticate first.', 'error')
        return redirect(url_for('index'))
    
    return render_template('snowflake_setup.html')


@app.route('/snowflake-interface')
def snowflake_interface():
    """Snowflake SQL execution interface"""
    snowflake_token = session.get('snowflake_token')
    if not snowflake_token:
        flash('No Snowflake token found. Please complete setup first.', 'error')
        return redirect(url_for('snowflake_setup'))
    
    account = session.get('snowflake_account', '')
    database = session.get('snowflake_database', '')
    schema = session.get('snowflake_schema', '')
    warehouse = session.get('snowflake_warehouse', '')
    role = session.get('snowflake_role', '')
    
    expires_at_str = session.get('snowflake_expires_at')
    if expires_at_str:
        expires_at = datetime.fromisoformat(expires_at_str)
        expires_in = max(0, int((expires_at - datetime.now()).total_seconds()))
    else:
        expires_at = datetime.now() + timedelta(hours=1)
        expires_in = 3600
    
    return render_template('snowflake_interface.html',
                         account=account,
                         database=database,
                         schema=schema,
                         warehouse=warehouse,
                         role=role,
                         expires_at=expires_at,
                         expires_in=expires_in)


@app.route('/api/execute-snowflake-sql', methods=['POST'])
def execute_snowflake_sql():
    """Execute SQL statement on Snowflake using OBO token"""
    snowflake_token = session.get('snowflake_token')
    if not snowflake_token:
        return jsonify({'error': 'No Snowflake token found'}), 401
    
    data = request.json
    sql_statement = data.get('statement')
    account = session.get('snowflake_account')
    database = session.get('snowflake_database')
    schema = session.get('snowflake_schema')
    warehouse = session.get('snowflake_warehouse')
    role = session.get('snowflake_role')
    
    if not sql_statement:
        return jsonify({'error': 'Missing SQL statement'}), 400
    
    if not account:
        return jsonify({'error': 'Snowflake account not configured'}), 400
    
    try:
        # Use OBO token with Snowflake SQL API
        # Handle both account name (e.g., "mycompany.us-east-1") and full hostname
        if '.snowflakecomputing.com' in account:
            # User provided full hostname
            snowflake_host = account
        else:
            # User provided account identifier only
            snowflake_host = f"{account}.snowflakecomputing.com"
        
        # Snowflake REST API endpoint
        url = f"https://{snowflake_host}/api/v2/statements"
        
        headers = {
            'Authorization': f'Bearer {snowflake_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-Snowflake-Authorization-Token-Type': 'OAUTH'
        }
        
        request_data = {
            'statement': sql_statement,
            'timeout': 60
        }
        
        # Add optional parameters if configured
        if database:
            request_data['database'] = database
        if schema:
            request_data['schema'] = schema
        if warehouse:
            request_data['warehouse'] = warehouse
        if role:
            request_data['role'] = role
        
        logger.info(f"Executing Snowflake SQL with OBO token: {sql_statement[:100]}...")
        logger.info(f"Snowflake account: {account}")
        logger.info(f"Snowflake URL: {url}")
        logger.info(f"Request data: database={database}, schema={schema}, warehouse={warehouse}, role={role}")
        
        response = requests.post(
            url,
            headers=headers,
            json=request_data,
            timeout=65
        )
        
        # Log response details before raising for status
        logger.info(f"Snowflake response status: {response.status_code}")
        
        if not response.ok:
            # Try to get detailed error from Snowflake
            try:
                error_body = response.json()
                logger.error(f"Snowflake error response: {error_body}")
            except:
                logger.error(f"Snowflake error response (raw): {response.text}")
        
        response.raise_for_status()
        return jsonify(response.json())
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Snowflake SQL execution error: {str(e)}")
        
        # Enhanced error detail extraction
        error_detail = str(e)
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_json = e.response.json()
                logger.error(f"Snowflake detailed error: {error_json}")
                error_detail = error_json
            except:
                error_text = e.response.text
                logger.error(f"Snowflake error text: {error_text}")
                error_detail = error_text
        
        return jsonify({'error': str(e), 'detail': error_detail}), 500


@app.route('/logout')
def logout():
    """Logout and clear session"""
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=config.port, debug=True)

