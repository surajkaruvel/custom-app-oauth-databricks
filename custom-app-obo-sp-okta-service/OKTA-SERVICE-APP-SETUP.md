# 🔧 Okta Service Application Setup Guide

This guide walks you through creating an **Okta Service Application** (API Services type) for machine-to-machine authentication with Databricks.

## 📋 Prerequisites

- Okta Admin Console access
- Databricks workspace admin access
- Understanding of OAuth Client Credentials flow

## 🚀 Step 1: Create Okta Service Application

### 1.1 Access Okta Admin Console

1. **Login** to your Okta Admin Console
2. Navigate to **Applications** → **Applications**

### 1.2 Create New Application

1. Click **"Create App Integration"**
2. **Select Integration Type:**
   - ✅ **API Services** (This is crucial - not Web Application or SPA)
   - Click **"Next"**

### 1.3 Configure Application Settings

**General Settings:**
```
App integration name: Databricks Service Principal
App logo: [Optional - upload if desired]
```

**Grant Types:**
- ✅ **Client Credentials** (Required for M2M)
- ❌ Authorization Code (Not needed)
- ❌ Implicit (Not needed)
- ❌ Resource Owner Password (Not needed)

**Application Type:**
- Should automatically be set to **"Service"**

### 1.4 Save and Get Credentials

1. Click **"Save"**
2. **Copy and securely store:**
   - **Client ID** (e.g., `0oabc123def456ghi789`)
   - **Client Secret** (e.g., `AbC123dEf456GhI789jKl012MnO345pQr678StU9`)

⚠️ **Important**: The client secret is only shown once. Store it securely!

## 🔐 Step 2: Configure OAuth Scopes

### 2.1 Set Allowed Scopes

1. In your **Service Application** settings
2. Go to **"Okta API Scopes"** tab
3. **Grant the following scopes:**
   - ✅ `okta.apps.read` (if needed for app management)
   - ✅ `okta.users.read` (if needed for user info)
   - Or configure **custom scopes** as needed

### 2.2 Custom Authorization Server (Recommended)

For better control, create a custom authorization server:

1. **Security** → **API** → **Authorization Servers**
2. **Add Authorization Server:**
   ```
   Name: Databricks Service Auth
   Audience: api://databricks
   Description: Authorization server for Databricks service principal
   ```

3. **Create Custom Scope:**
   ```
   Name: all-apis
   Description: Access to all Databricks APIs
   ```

4. **Create Access Policy:**
   ```
   Name: Service Principal Policy
   Description: Allow service principal access
   Assign to: Your service application
   ```

5. **Create Rule:**
   ```
   Rule Name: Allow All APIs
   Grant type: Client Credentials
   Scopes: all-apis
   ```

## 🏢 Step 3: Configure Databricks Federation

### 3.1 Create Federation Policy

In Databricks SQL or a notebook, create a federation policy:

```sql
-- Replace with your actual Okta domain and auth server ID
CREATE FEDERATION POLICY okta_service_federation
ISSUER 'https://your-okta-domain.okta.com/oauth2/your-auth-server-id'
AUDIENCE 'api://databricks'
SUBJECT_MAPPING 'sub'
COMMENT 'Federation policy for Okta service principal';
```

### 3.2 Create Service Principal in Databricks

```sql
-- Create service principal using the Okta client ID
CREATE SERVICE PRINCIPAL 'your-okta-client-id'
COMMENT 'Service principal for automated SQL queries';
```

### 3.3 Grant Permissions

```sql
-- Grant necessary permissions
GRANT USE CATALOG ON CATALOG main TO SERVICE PRINCIPAL 'your-okta-client-id';
GRANT USE SCHEMA ON SCHEMA main.default TO SERVICE PRINCIPAL 'your-okta-client-id';
GRANT SELECT ON TABLE main.default.* TO SERVICE PRINCIPAL 'your-okta-client-id';

-- For SQL warehouses
GRANT USAGE ON SQL WAREHOUSE 'your-warehouse-id' TO SERVICE PRINCIPAL 'your-okta-client-id';
```

## ⚙️ Step 4: Application Configuration

### 4.1 Update config.env

```bash
# Okta Service Application Configuration
ISSUER_URL=https://your-okta-domain.okta.com/oauth2/your-auth-server-id
CLIENT_ID=your-service-app-client-id-here
CLIENT_SECRET=your-service-app-client-secret-here
OAUTH_SCOPE=all-apis

# Databricks Configuration
DATABRICKS_SERVER_HOSTNAME=your-workspace.cloud.databricks.com
DATABRICKS_HTTP_PATH=/sql/1.0/warehouses/your-warehouse-id
```

### 4.2 Key Configuration Notes

**ISSUER_URL Format:**
- **Default Auth Server**: `https://your-domain.okta.com/oauth2/default`
- **Custom Auth Server**: `https://your-domain.okta.com/oauth2/your-server-id`

**CLIENT_ID:**
- This is the **Application ID** from your Okta Service Application
- Format: `0oaXXXXXXXXXXXXXXXX` (starts with `0oa`)

**CLIENT_SECRET:**
- The secret generated when you created the Service Application
- Keep this secure and never commit to version control

## 🧪 Step 5: Testing the Setup

### 5.1 Test Okta Token Acquisition

```bash
curl -X POST "https://your-okta-domain.okta.com/oauth2/your-auth-server-id/v1/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET&scope=all-apis"
```

**Expected Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "all-apis"
}
```

### 5.2 Test Databricks Token Exchange

```bash
curl -X POST "https://your-workspace.cloud.databricks.com/oidc/v1/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=YOUR_OKTA_ACCESS_TOKEN&subject_token_type=urn:ietf:params:oauth:token-type:access_token&scope=all-apis"
```

### 5.3 Test Application Health

```bash
# Start your application
python app.py

# Check health endpoint
curl http://localhost:7000/health
```

**Expected Response:**
```json
{
  "status": "healthy",
  "service_principal_configured": true,
  "okta_configured": true,
  "databricks_configured": true,
  "tokens_valid": true,
  "app_type": "Service Principal (M2M)",
  "authentication_flow": "OAuth Client Credentials"
}
```

## 🔍 Troubleshooting

### Common Issues

**1. "invalid_client" Error**
- **Cause**: Wrong `CLIENT_ID` or `CLIENT_SECRET`
- **Solution**: Verify credentials in Okta Admin Console

**2. "invalid_scope" Error**
- **Cause**: Scope not granted to the application
- **Solution**: Check OAuth scopes in Okta application settings

**3. "Token exchange failed: 401 Unauthorized"**
- **Cause**: Federation policy not configured or service principal doesn't exist
- **Solution**: Verify Databricks federation setup

**4. "unsupported_grant_type" Error**
- **Cause**: Client Credentials grant type not enabled
- **Solution**: Enable "Client Credentials" in Okta application settings

### Debug Steps

1. **Verify Okta Configuration:**
   ```bash
   # Check if you can get a token from Okta
   curl -v -X POST "https://your-domain.okta.com/oauth2/your-server/v1/token" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=client_credentials&client_id=YOUR_ID&client_secret=YOUR_SECRET&scope=all-apis"
   ```

2. **Check Token Content:**
   ```bash
   # Decode the JWT token to verify claims
   echo "YOUR_ACCESS_TOKEN" | cut -d. -f2 | base64 -d | jq
   ```

3. **Verify Databricks Federation:**
   ```sql
   -- Check if federation policy exists
   SHOW FEDERATION POLICIES;
   
   -- Check if service principal exists
   SHOW SERVICE PRINCIPALS;
   ```

## 📚 Reference Links

- [Okta API Services Documentation](https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/)
- [OAuth Client Credentials Flow](https://oauth.net/2/grant-types/client-credentials/)
- [Databricks Federation Documentation](https://docs.databricks.com/security/auth/federation.html)

## ✅ Checklist

Before proceeding, ensure:

- [ ] Okta Service Application created with "API Services" type
- [ ] Client Credentials grant type enabled
- [ ] Client ID and Client Secret obtained
- [ ] Custom authorization server created (recommended)
- [ ] Databricks federation policy configured
- [ ] Service principal created in Databricks
- [ ] Appropriate permissions granted
- [ ] Application configuration updated
- [ ] Health check passes

---

**🎉 Once complete, your service principal app will authenticate automatically without any user interaction!**
