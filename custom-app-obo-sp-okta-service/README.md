# 🤖 Databricks SQL Interface - Service Principal (M2M)

A machine-to-machine (M2M) application that uses **Okta Service Application** for automatic authentication with Databricks. No user interaction required!

## 🎯 Key Features

- **🤖 Machine-to-Machine**: No user authentication required
- **🔐 OAuth Client Credentials**: Secure service-to-service authentication
- **🔄 Auto Token Management**: Automatic token acquisition and refresh
- **📊 SQL Interface**: Execute queries on any Databricks SQL warehouse
- **🛡️ Enterprise Security**: Okta Service Application with client credentials
- **⚡ Zero User Interaction**: Perfect for automation and services

## 🏗️ Architecture

```
Service Principal App → Okta Service App → Databricks Workspace
                     (Client Credentials)    (Token Exchange)
```

**Flow:**
1. App authenticates with Okta using **Client Credentials** flow
2. Receives Okta access token (no user involved)
3. Exchanges Okta token for Databricks workspace token
4. Executes SQL queries using workspace token
5. Automatically refreshes tokens when needed

## 🚀 Quick Start

### 1. Prerequisites

- Python 3.8+
- Okta Service Application (API Services type)
- Databricks workspace with federation configured

### 2. Installation

```bash
# Clone or navigate to the project
cd external-oauth-sp

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configuration

```bash
# Copy example configuration
cp config.env.example config.env

# Edit config.env with your values
nano config.env
```

**Required Configuration:**
```bash
# Okta Service Application
ISSUER_URL=https://your-okta-domain.okta.com/oauth2/your-auth-server-id
CLIENT_ID=your-service-app-client-id
CLIENT_SECRET=your-service-app-client-secret

# Databricks
DATABRICKS_SERVER_HOSTNAME=your-workspace.cloud.databricks.com
DATABRICKS_HTTP_PATH=/sql/1.0/warehouses/your-warehouse-id  # Optional
```

### 4. Run the Application

```bash
# Activate virtual environment
source venv/bin/activate

# Start the app
python app.py
```

The app will start on **http://localhost:7000**

## 📋 Setup Guide

### Step 1: Create Okta Service Application

1. **Login to Okta Admin Console**
2. **Applications** → **Create App Integration**
3. **Select "API Services"** (not Web Application or SPA)
4. **Configure:**
   - **App integration name**: `Databricks Service Principal`
   - **Grant types**: ✅ Client Credentials
   - **Scopes**: `databricks-token-federation`

5. **Save and note:**
   - **Client ID**
   - **Client Secret**

### Step 2: Configure Databricks Federation

Create a federation policy in Databricks to accept Okta tokens:

```sql
-- In Databricks SQL or notebook
CREATE FEDERATION POLICY okta_federation
ISSUER 'https://your-okta-domain.okta.com/oauth2/your-auth-server-id'
AUDIENCE 'api://databricks'
SUBJECT_MAPPING 'sub'
```

### Step 3: Create Databricks Service Principal

```sql
-- Create service principal in Databricks
CREATE SERVICE PRINCIPAL 'your-okta-client-id'
```

### Step 4: Grant Permissions

```sql
-- Grant necessary permissions to the service principal
GRANT USE CATALOG ON CATALOG main TO SERVICE PRINCIPAL 'your-okta-client-id';
GRANT USE SCHEMA ON SCHEMA main.default TO SERVICE PRINCIPAL 'your-okta-client-id';
GRANT SELECT ON TABLE main.default.* TO SERVICE PRINCIPAL 'your-okta-client-id';
```

## 🔧 Configuration Options

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `PORT` | Application port | No | `7000` |
| `FLASK_DEBUG` | Debug mode | No | `True` |
| `ISSUER_URL` | Okta authorization server URL | Yes | - |
| `CLIENT_ID` | Okta service app client ID | Yes | - |
| `CLIENT_SECRET` | Okta service app client secret | Yes | - |
| `OAUTH_SCOPE` | OAuth scope for Okta | No | `databricks-token-federation` |
| `DATABRICKS_SERVER_HOSTNAME` | Databricks workspace hostname | Yes | - |
| `DATABRICKS_HTTP_PATH` | Default warehouse path | No | - |

## 🛠️ API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main page with app overview |
| `/sql` | GET | SQL query interface |
| `/execute-sql` | POST | Execute SQL query |
| `/health` | GET | Health check and status |
| `/token-status` | GET | Current token information |
| `/refresh-tokens` | POST | Manually refresh tokens |

## 📊 Usage Examples

### Execute SQL via Web Interface

1. Open **http://localhost:7000**
2. Click **"Open SQL Interface"**
3. Enter your **Warehouse ID**
4. Enter your **SQL query**
5. Click **"Execute Query"**

### Execute SQL via API

```bash
curl -X POST http://localhost:7000/execute-sql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "SELECT current_timestamp(), current_user()",
    "warehouse_id": "your-warehouse-id"
  }'
```

### Check Health Status

```bash
curl http://localhost:7000/health
```

## 🔍 Troubleshooting

### Common Issues

**1. "Service principal token request failed"**
- Check Okta `CLIENT_ID` and `CLIENT_SECRET`
- Verify `ISSUER_URL` is correct
- Ensure Okta Service Application has "Client Credentials" grant type

**2. "Workspace token exchange failed: 401 Unauthorized"**
- Verify Databricks federation policy is configured
- Check if service principal exists in Databricks
- Ensure `DATABRICKS_SERVER_HOSTNAME` is correct

**3. "SQL execution failed"**
- Verify warehouse ID is correct and running
- Check service principal has permissions on the data
- Ensure warehouse is accessible

### Debug Mode

Enable debug logging:
```bash
export FLASK_DEBUG=True
python app.py
```

### Health Check

Visit **http://localhost:7000/health** to see:
- Service principal configuration status
- Token validity
- Databricks connectivity
- Overall app health

## 🔐 Security Considerations

- **Client Secret Protection**: Store `CLIENT_SECRET` securely
- **Network Security**: Use HTTPS in production
- **Token Scope**: Use minimal required OAuth scopes
- **Access Control**: Grant minimal Databricks permissions
- **Monitoring**: Monitor token usage and API calls

## 🚀 Production Deployment

### Environment Variables

Set configuration via environment variables instead of `config.env`:

```bash
export ISSUER_URL="https://your-okta-domain.okta.com/oauth2/your-auth-server-id"
export CLIENT_ID="your-service-app-client-id"
export CLIENT_SECRET="your-service-app-client-secret"
export DATABRICKS_SERVER_HOSTNAME="your-workspace.cloud.databricks.com"
export PORT=7000
export FLASK_DEBUG=False
```

### Production Server

Use a production WSGI server:

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:7000 app:app
```

### Docker Deployment

```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 7000
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:7000", "app:app"]
```

## 📚 Additional Resources

- [Okta API Services Documentation](https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/)
- [Databricks OAuth Documentation](https://docs.databricks.com/dev-tools/auth.html)
- [OAuth Client Credentials Flow](https://oauth.net/2/grant-types/client-credentials/)

## 🤝 Support

For issues and questions:
1. Check the **Health** endpoint: `/health`
2. Review application logs
3. Verify Okta and Databricks configuration
4. Test with minimal SQL queries first

---

**🤖 Perfect for automation, CI/CD pipelines, and service-to-service integrations!**
