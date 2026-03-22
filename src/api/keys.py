from uuid import UUID

from fastapi import APIRouter

router = APIRouter(prefix="/keys", tags=["api-keys"])


@router.post("/")
async def create_api_key(tenant_id: UUID, name: str, permissions: list):
    """Create new API key"""
    return {
        "key": "mpesa_live_sk_12345abcdef",  # Only shown once
        "preview": "abcd",
        "name": name,
    }


@router.get("/")
async def list_api_keys(tenant_id: UUID):
    """List all API keys for tenant"""
    return {"keys": []}


@router.delete("/{key_id}")
async def revoke_api_key(key_id: UUID):
    """Revoke API key"""
    return {"message": "Key revoked"}


@router.post("/{key_id}/rotate")
async def rotate_api_key(key_id: UUID):
    """Rotate API key"""
    return {"new_key": "mpesa_live_sk_newkey123"}
