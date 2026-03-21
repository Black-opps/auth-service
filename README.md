# 🟦 Auth Service - Authentication & Authorization Microservice

[![FastAPI](https://img.shields.io/badge/FastAPI-0.104.0-009688.svg?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.11-3776AB.svg?style=for-the-badge&logo=python)](https://www.python.org)
[![JWT](https://img.shields.io/badge/JWT-Security-000000.svg?style=for-the-badge&logo=json-web-tokens)](https://jwt.io)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-336791.svg?style=for-the-badge&logo=postgresql)](https://www.postgresql.org)
[![Redis](https://img.shields.io/badge/Redis-7.0-DC382D.svg?style=for-the-badge&logo=redis)](https://redis.io)

Centralized authentication and authorization service for the M-PESA SaaS platform. Handles user authentication, JWT tokens, API keys, MFA, and session management.

## 📋 Overview

The Auth Service provides enterprise-grade security features for the entire M-PESA SaaS ecosystem:

- **JWT Authentication** - Access and refresh tokens with short-lived access tokens
- **API Key Management** - Create, rotate, and revoke API keys with granular permissions
- **Multi-Factor Authentication (MFA)** - TOTP support with QR codes and backup codes
- **Session Management** - Track active sessions with Redis caching
- **Rate Limiting** - Protect against brute force attacks
- **Password Policy** - Enforce strong passwords with configurable rules
- **SSO Ready** - Foundation for Google/Microsoft SSO integration
- **RBAC** - Role-based access control with granular permissions

## 🏗️ Architecture

┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ API Layer │────▶│ Service Layer │────▶│ Model Layer │
│ (FastAPI) │ │ (Business │ │ (SQLAlchemy) │
│ │ │ Logic) │ │ │
└─────────────────┘ └─────────────────┘ └─────────────────┘
│ │ │
▼ ▼ ▼
┌─────────────────────────────────────────────────────────────┐
│ PostgreSQL │
│ Redis (Sessions) │
└─────────────────────────────────────────────────────────────┘

text

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- PostgreSQL 15+
- Redis 7+

### Installation

1. **Clone and navigate**

```bash
cd services/auth-service
Create virtual environment

bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows
Install dependencies

bash
pip install -r requirements.txt
Set up environment variables

bash
cp .env.example .env
# Edit .env with your configuration
Run database migrations

bash
alembic upgrade head
Start the service

bash
uvicorn src.main:app --reload --port 8007
Docker
bash
# Build
docker build -t auth-service .

# Run
docker run -p 8007:8007 --env-file .env auth-service
📚 API Documentation
Once running, access:

Swagger UI: http://localhost:8007/api/docs

ReDoc: http://localhost:8007/api/redoc

OpenAPI JSON: http://localhost:8007/api/openapi.json

Metrics: http://localhost:8007/metrics

Health Check: http://localhost:8007/health

🔌 API Endpoints
Authentication
Method	Endpoint	Description
POST	/api/v1/auth/login	Login with email/password
POST	/api/v1/auth/refresh	Refresh access token
POST	/api/v1/auth/logout	Logout current session
POST	/api/v1/auth/logout-all	Logout from all devices
POST	/api/v1/auth/change-password	Change password
POST	/api/v1/auth/reset-password	Request password reset
POST	/api/v1/auth/reset-password/confirm	Confirm password reset
GET	/api/v1/auth/verify-email	Verify email address
API Keys
Method	Endpoint	Description
GET	/api/v1/keys	List all API keys
POST	/api/v1/keys	Create new API key
GET	/api/v1/keys/{key_id}	Get API key details
PUT	/api/v1/keys/{key_id}	Update API key
DELETE	/api/v1/keys/{key_id}	Revoke API key
POST	/api/v1/keys/{key_id}/rotate	Rotate API key
MFA
Method	Endpoint	Description
POST	/api/v1/mfa/setup	Setup TOTP MFA
POST	/api/v1/mfa/verify	Verify MFA code
POST	/api/v1/mfa/disable	Disable MFA
POST	/api/v1/mfa/backup-codes	Generate backup codes
POST	/api/v1/mfa/verify-backup	Verify backup code
Sessions
Method	Endpoint	Description
GET	/api/v1/sessions	List active sessions
DELETE	/api/v1/sessions/{session_id}	Terminate session
DELETE	/api/v1/sessions	Terminate all sessions
Token Introspection
Method	Endpoint	Description
POST	/api/v1/tokens/introspect	Validate token
POST	/api/v1/tokens/revoke	Revoke token
📊 Data Models
User
json
{
  "id": "uuid",
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "role": "admin",
  "status": "active",
  "email_verified": true,
  "mfa_enabled": false,
  "created_at": "2026-03-18T10:30:00Z"
}
API Key
json
{
  "id": "uuid",
  "name": "Production API Key",
  "key_preview": "mpesa_live_...a1b2",
  "permissions": ["read:transactions", "write:transactions"],
  "ip_restrictions": ["192.168.1.100"],
  "expires_at": "2027-03-18T10:30:00Z",
  "last_used_at": "2026-03-18T10:30:00Z"
}
Session
json
{
  "id": "uuid",
  "user_agent": "Mozilla/5.0...",
  "ip_address": "192.168.1.100",
  "country": "Kenya",
  "city": "Nairobi",
  "created_at": "2026-03-18T10:30:00Z",
  "last_activity": "2026-03-18T11:30:00Z"
}
🔒 Security Features
Password Policy
Minimum 8 characters

Requires uppercase, lowercase, numbers, special characters

Password history (prevents reuse)

Max age 90 days (configurable)

Rate Limiting
100 requests per minute per IP

Configurable limits per endpoint

Redis-backed rate limiting

JWT Security
Short-lived access tokens (15 minutes)

Refresh tokens with rotation

Token revocation


### This completes the Auth Service implementation with:

✅ JWT authentication with access/refresh tokens

✅ API key management with permissions

✅ MFA support (TOTP with QR codes)

✅ Session management with Redis

✅ Rate limiting

✅ Password policy enforcement

✅ SSO foundation (Google/Microsoft ready)

✅ Security best practices

✅ Comprehensive logging and monitoring

The service is production-ready and follows all security best practices! 🎉
```
