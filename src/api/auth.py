from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

router = APIRouter(prefix="/auth", tags=["auth"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@router.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Login and get access token"""
    return {
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "token_type": "bearer",
        "expires_in": 3600
    }

@router.post("/refresh")
async def refresh_token(refresh_token: str):
    """Refresh access token"""
    return {"access_token": "new_token", "expires_in": 3600}

@router.post("/logout")
async def logout(token: str = Depends(oauth2_scheme)):
    """Logout and invalidate token"""
    return {"message": "Logged out"}

@router.get("/me")
async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Get current user info"""
    return {"user_id": "123", "email": "user@example.com"}

@router.post("/change-password")
async def change_password(old_password: str, new_password: str, token: str = Depends(oauth2_scheme)):
    """Change user password"""
    return {"message": "Password changed"}
