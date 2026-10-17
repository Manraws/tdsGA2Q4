from fastapi.responses import JSONResponse
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import jwt

app = FastAPI(title="OAuth 2.0 / OIDC Token Verification")

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-y7zctkwp.apps.exam.local"
ALGORITHM = "RS256"

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""


class VerifyRequest(BaseModel):
    token: str


@app.get("/")
def home():
    return {"service": "JWT Verification Service", "status": "running"}


@app.post("/verify")
def verify_token(request: VerifyRequest):
    try:
        claims = jwt.decode(
            request.token,
            PUBLIC_KEY,
            algorithms=[ALGORITHM],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={
                "require": ["exp", "iss", "aud", "sub", "email"]
            },
        )

        return {
            "valid": True,
            "email": claims["email"],
            "sub": claims["sub"],
            "aud": claims["aud"],
        }

    except jwt.InvalidTokenError:
        return JSONResponse(
            status_code=401,
            content={"valid": False},
        )