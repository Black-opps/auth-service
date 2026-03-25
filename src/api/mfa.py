# src/api/mfa.py
from fastapi import APIRouter

router = APIRouter(
    prefix="/mfa",
    tags=["mfa"],
    responses={404: {"description": "Not found"}},
)


@router.get("/test")
async def mfa_test():
    return {"message": "MFA router placeholder"}
