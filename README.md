# Beekeeper API - User Authentication System

A FastAPI-based authentication system with OAuth support, built with SQLAlchemy and PostgreSQL.

## 🚀 Features

- **User Authentication**: Registration, login, logout
- **JWT Tokens**: Access and refresh token management
- **Password Management**: Secure password hashing and reset functionality
- **Email Verification**: Email-based account verification
- **OAuth Integration**: Google, Apple, and Microsoft authentication
- **Database**: PostgreSQL with Alembic migrations
- **Security**: CSRF protection, rate limiting, secure headers

## 📋 Prerequisites

- Python 3.9+
- PostgreSQL 12+
- uv package manager (recommended) or pip

## 🛠️ Installation & Setup

### 1. Clone the Repository

```bash
git clone <repository-url>
cd user-auth/backend
```

### 2. Install uv (Package Manager)

[uv](https://github.com/astral-sh/uv) is a fast Python package installer and resolver, written in Rust. It's significantly faster than pip and provides better dependency resolution.

```bash
# Install uv using pip
pip install uv

# Or install using curl (macOS/Linux)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Or install using Homebrew (macOS)
brew install uv

# Verify installation
uv --version
```

### 3. Create Virtual Environment

```bash
# Using uv (recommended)
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### 4. Install Dependencies

```bash
# Using uv
uv sync
```


### 4. Environment Configuration

Create a `.env` file in the backend directory:

```bash
# Base settings
PROJECT_NAME=Beekeeper
VERSION=1.0.0
API_V1_STR=/api/v1

# Security
SECRET_KEY=your-secret-key-here-change-in-production
JWT_ALGORITHM=HS256

# Database (Update with your database details)
DATABASE_URL=postgresql://username:password@localhost:5432/database_name

# JWT Settings
ACCESS_TOKEN_EXPIRE_MINUTES=1440
REFRESH_TOKEN_EXPIRE_DAYS=7

# Security Settings
MAX_LOGIN_ATTEMPTS=5

# OAuth Settings (Optional - for OAuth features)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:3000/auth/google/callback

# Frontend URL (for CORS)
FRONTEND_URL=http://localhost:3000
BACKEND_URL=http://localhost:8000
BACKEND_CORS_ORIGINS=http://localhost:3000,http://localhost:3001

# Email Settings (Optional - for email features)
RESEND_API_KEY=your-resend-api-key
EMAILS_FROM_EMAIL=noreply@beekeeper.com
EMAILS_FROM_NAME=Beekeeper Team
EMAIL_ENABLED=true

# Application Settings
ENVIRONMENT=development

# CSRF Settings
CSRF_ENABLED=false
CSRF_COOKIE_SECURE=false
CSRF_COOKIE_HTTP_ONLY=true
CSRF_COOKIE_SAMESITE=lax
CSRF_COOKIE_MAX_AGE=3600
```

### 5. Database Setup

#### Option A: Local PostgreSQL

1. Install PostgreSQL
2. Create a database:
```bash
createdb beekeeper
```

#### Option B: Supabase (Recommended for development)

1. Create a Supabase project at [supabase.com](https://supabase.com)
2. Get your database connection string from the project settings
3. Update `DATABASE_URL` in your `.env` file

## 🗄️ Database Migrations with Alembic

### 1. Initialize Alembic (First time only)

```bash
# Make sure you're in the backend directory
cd backend

# Initialize Alembic
alembic init alembic
```

### 2. Configure Alembic

Update `alembic/env.py` to use your database configuration:

```python
# Add this import at the top
from app.core.config import settings

# Update the database URL configuration
database_url = os.getenv("DATABASE_URL", settings.DATABASE_URL)
```

### 3. Create Initial Migration

```bash
# Create the initial migration for the beekeeper schema
alembic revision --autogenerate -m "Initial migration for beekeeper schema"
```

### 4. Run Migrations

```bash
# Apply all pending migrations
alembic upgrade head

# Check migration status
alembic current

# View migration history
alembic history
```

### 5. Migration Commands Reference

```bash
# Create a new migration
alembic revision --autogenerate -m "Description of changes"

# Apply migrations
alembic upgrade head          # Apply all pending migrations
alembic upgrade +1            # Apply next migration
alembic upgrade <revision>    # Apply up to specific revision

# Rollback migrations
alembic downgrade -1          # Rollback one migration
alembic downgrade <revision>  # Rollback to specific revision
alembic downgrade base        # Rollback all migrations

# Check status
alembic current               # Show current revision
alembic heads                 # Show latest revisions
alembic show <revision>       # Show migration details
```

## 🚀 Running the Application

### 1. Start the Server

```bash
# Development mode with auto-reload
uvicorn app.main:app --reload --port 8000

# Or using the start script
./start.sh
```

### 2. Verify the Application

```bash
# Health check
curl http://localhost:8000/api/v1/health

# API documentation
open http://localhost:8000/api/docs
```

## 🧪 Testing the Authentication Flow

### 1. User Registration

```bash
curl -X POST "http://localhost:8000/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "ValidPassword123"
  }'
```

**Note**: Use passwords without special characters (like `!`) to avoid URL encoding issues in curl commands.

### 2. User Login

```bash
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -d "username=test@example.com&password=ValidPassword123"
```

### 3. User Logout

```bash
# Use the refresh_token from login response
curl -X POST "http://localhost:8000/api/v1/auth/logout?refresh_token=YOUR_REFRESH_TOKEN"
```

### 4. Password Reset Request

```bash
curl -X POST "http://localhost:8000/api/v1/auth/request-password-reset" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com"}'
```

## 📁 Project Structure

```
backend/
├── alembic/                 # Database migrations
│   ├── versions/           # Migration files
│   ├── env.py             # Alembic environment
│   └── alembic.ini        # Alembic configuration
├── app/
│   ├── core/              # Core configuration
│   │   ├── config.py      # Settings and configuration
│   │   ├── database.py    # Database connection
│   │   └── security.py    # Security utilities
│   ├── models/            # Database models
│   │   ├── user.py        # User model
│   │   └── token.py       # Token models
│   ├── routes/            # API routes
│   │   └── auth.py        # Authentication endpoints
│   ├── services/          # Business logic
│   │   └── auth.py        # Authentication service
│   └── main.py            # FastAPI application
├── .env                   # Environment variables
├── pyproject.toml         # Project dependencies
└── README.md              # This file
```

## 🔧 Configuration Options

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ENVIRONMENT` | Application environment | `development` |
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `SECRET_KEY` | JWT signing key | Required |
| `EMAIL_ENABLED` | Enable email functionality | `true` |
| `CSRF_ENABLED` | Enable CSRF protection | `false` |

### Database Schema

The application uses the `beekeeper` schema by default. All tables are created in this schema:

- `users` - User accounts and profiles
- `tokens` - JWT token storage
- `verification_tokens` - Email verification tokens
- `password_reset_tokens` - Password reset tokens
- `social_accounts` - OAuth account connections

## 🚨 Troubleshooting

### Common Issues

1. **Database Connection Errors**
   - Verify `DATABASE_URL` in `.env`
   - Ensure PostgreSQL is running
   - Check database permissions

2. **Migration Errors**
   - Ensure all models are properly imported
   - Check for schema conflicts
   - Verify Alembic configuration

3. **Authentication Errors**
   - Check JWT secret key configuration
   - Verify token expiration settings
   - Ensure database tables exist

4. **Email Service Errors**
   - Verify Resend API key configuration
   - Check email service settings
   - Ensure `EMAIL_ENABLED=true`

### Debug Mode

Enable debug logging by setting:

```bash
export LOG_LEVEL=DEBUG
```

## 📚 API Documentation

Once the server is running, visit:
- **Swagger UI**: http://localhost:8000/api/docs
- **ReDoc**: http://localhost:8000/api/redoc
- **OpenAPI JSON**: http://localhost:8000/api/v1/openapi.json

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 🆘 Support

For issues and questions:
1. Check the troubleshooting section
2. Review the API documentation
3. Open an issue on GitHub
4. Contact the development team

---

**Happy coding! 🚀**
