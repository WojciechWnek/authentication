from datetime import UTC, datetime, timedelta

import jwt
from pwdlib import PasswordHash

from settings import settings

password_hash = PasswordHash.recommended()

DUMMY_HASH = password_hash.hash("dummy-password-for-timing-attack-prevention")
ACCESS_TOKEN_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRATION_TIME_IN_MINUTES = 10


def hash_password(plain_password: str):
    return password_hash.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str):
    return password_hash.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_deta: timedelta | None = None) -> str:
    now = datetime.now(UTC)

    if expires_deta:
        expiration_time = now + expires_deta
    else:
        expiration_time = now + timedelta(
            minutes=ACCESS_TOKEN_EXPIRATION_TIME_IN_MINUTES
        )

    payload = {**data, "iat": now, "exp": expiration_time}

    return jwt.encode(
        payload=payload, key=settings.JWT_SECRET_KEY, algorithm=ACCESS_TOKEN_ALGORITHM
    )
