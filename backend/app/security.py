import hashlib
import hmac
import secrets
from datetime import timedelta
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from .db import Session, SessionLocal, User, now

bearer = HTTPBearer(auto_error=False)

def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
    return f"scrypt${salt.hex()}${digest.hex()}"

def verify_password(password: str, encoded: str) -> bool:
    try:
        _, salt, expected = encoded.split("$")
        actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1)
        return hmac.compare_digest(actual.hex(), expected)
    except (ValueError, TypeError):
        return False

def digest_token(token):
    return hashlib.sha256(token.encode()).hexdigest()

def issue_session(db, user):
    token = secrets.token_urlsafe(48)
    db.add(Session(token_hash=digest_token(token), user_id=user.id, expires_at=now() + timedelta(hours=1)))
    return token

def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> User:
    if credentials is None:
        raise HTTPException(401, "Authentication required")
    with SessionLocal() as db:
        session = db.get(Session, digest_token(credentials.credentials))
        if session is None or session.expires_at.replace(tzinfo=now().tzinfo) <= now():
            raise HTTPException(401, "Session expired or invalid")
        user = db.get(User, session.user_id)
        if user is None:
            raise HTTPException(401, "Session invalid")
        return user

def require(*roles):
    def check(user: User = Depends(current_user)):
        if user.role not in roles:
            raise HTTPException(403, "This operation is not permitted for your role")
        return user
    return check

analyst = require("Administrator", "Security Analyst")
admin = require("Administrator")
