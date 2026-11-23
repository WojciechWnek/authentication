import secrets
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Body, Depends, FastAPI, HTTPException, Security, status
from fastapi.security import (
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
    SecurityScopes,
)
from sqlmodel import select

from database import SessionDep, create_db_and_tables
from models import (
    PasswordResetConfirm,
    PasswordResetRequest,
    PasswordResetToken,
    User,
    UserCreate,
    UserResponse,
    UserUpdate,
)
from security import (
    DUMMY_HASH,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    scopes={
        "read:users": "Read users",
        "write:users": "Create and update users",
        "delete:users": "Delete users",
    },
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield


app = FastAPI(lifespan=lifespan)


def get_current_user(
    session: SessionDep, token: Annotated[str, Depends(oauth2_scheme)]
) -> User:
    invalid_token_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    payload = decode_token(token)
    if not payload:
        raise invalid_token_exception

    if payload.get("type") != "access":
        raise invalid_token_exception

    email = payload.get("sub")
    if not email:
        raise invalid_token_exception

    user = session.exec(select(User).where(User.email == email)).first()
    if not user:
        raise invalid_token_exception

    return user


def get_current_user_with_scope_check(
    current_user: Annotated[User, Depends(get_current_user)],
    token: Annotated[str, Depends(oauth2_scheme)],
    security_scopes: SecurityScopes,
) -> User:
    payload = decode_token(token)
    assert payload is not None

    user_scopes = payload.get("scopes", [])

    for scope in security_scopes.scopes:
        if scope not in user_scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
                headers={"WWW-Authenticate": "Bearer"},
            )

    return current_user


CurrentUser = Annotated[User, Depends(get_current_user)]

Role = Literal["user", "admin"]


class RoleRequired:
    def __init__(self, role: Role):
        self.role = role

    def __call__(self, current_user: CurrentUser):
        if current_user.role != self.role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action requires the '{self.role}' role",
            )

        return current_user


@app.post("/register", status_code=status.HTTP_201_CREATED, response_model=UserResponse)
def register(session: SessionDep, user_data: UserCreate):
    existing_user = session.exec(
        select(User).where(User.email == user_data.email)
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered"
        )

    new_user = User(
        email=user_data.email, hashed_password=hash_password(user_data.password)
    )

    session.add(new_user)
    session.commit()
    session.refresh(new_user)

    return new_user


@app.post("/token")
def login(
    session: SessionDep, form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    existing_user = session.exec(
        select(User).where(User.email == form_data.username)
    ).first()

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not existing_user:
        verify_password(form_data.password, DUMMY_HASH)
        raise credentials_exception

    if not verify_password(form_data.password, existing_user.hashed_password):
        raise credentials_exception

    data = {"sub": existing_user.email, "scopes": form_data.scopes}
    access_token = create_access_token(data=data)
    refresh_token = create_refresh_token(data=data)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@app.post("/token/refresh")
def refresh_token(session: SessionDep, refresh_token: Annotated[str, Body(embed=True)]):
    invalid_token_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
    )

    payload = decode_token(refresh_token)
    if not payload:
        raise invalid_token_exception

    if payload.get("type") != "refresh":
        raise invalid_token_exception

    email = payload.get("sub")
    if not email:
        raise invalid_token_exception

    user = session.exec(select(User).where(User.email == email)).first()
    if not user:
        raise invalid_token_exception

    new_access_token = create_access_token(data={"sub": user.email})
    return {"access_token": new_access_token, "token_type": "bearer"}


user_router = APIRouter(dependencies=[Depends(get_current_user)], tags=["users"])


@user_router.get("/me", status_code=status.HTTP_200_OK, response_model=UserResponse)
def get_me(current_user: CurrentUser):
    return current_user


@user_router.patch("/me", response_model=UserResponse)
def update_me(
    session: SessionDep, current_user: CurrentUser, update_payload: UserUpdate
):
    if not update_payload.email:
        return current_user

    user_with_email = session.exec(
        select(User).where(User.email == update_payload.email)
    ).first()

    if user_with_email and user_with_email.id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already taken"
        )

    current_user.email = update_payload.email

    session.add(current_user)
    session.commit()
    session.refresh(current_user)

    return current_user


@user_router.get("/dashboard")
def dashboard():
    return {"Profit": 1_000_000}


@app.post("/password-reset/request")
def request_password_reset(session: SessionDep, payload: PasswordResetRequest):
    message = {
        "message": "If an account exists with this email, a reset link has been sent"
    }

    user = session.exec(select(User).where(User.email == payload.email)).first()

    if not user or not user.id:
        return message

    token = secrets.token_urlsafe(32)

    reset_token = PasswordResetToken(
        token=token,
        user_id=user.id,
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
        used=False,
    )
    session.add(reset_token)
    session.commit()
    # In production: send an email to the user with the contents of token
    # Here's the link to you reset your password
    # i.e. send_reset_email(user.email, token)

    return message


@app.post("/password-reset/confirm")
def confirm_password_reset(session: SessionDep, payload: PasswordResetConfirm):
    invalid_token_error = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid reset token",
    )

    reset_token = session.exec(
        select(PasswordResetToken).where(PasswordResetToken.token == payload.token)
    ).first()

    if not reset_token:
        raise invalid_token_error

    if reset_token.used:
        raise invalid_token_error

    token_expired = reset_token.expires_at < datetime.now(UTC).replace(tzinfo=None)
    if token_expired:
        raise invalid_token_error

    user = session.get(User, reset_token.user_id)
    if not user:
        raise invalid_token_error

    user.hashed_password = hash_password(payload.new_password)
    session.add(user)

    reset_token.used = True
    session.add(reset_token)

    session.commit()

    return {"message": "Password reset successfully"}


admin_router = APIRouter(
    prefix="/admin", dependencies=[Depends(RoleRequired("admin"))], tags=["admin"]
)


@admin_router.get(
    "/users",
    response_model=list[UserResponse],
    dependencies=[Security(get_current_user_with_scope_check, scopes=["read:users"])],
)
def get_all_users(session: SessionDep):
    return session.exec(select(User)).all()


@admin_router.delete(
    "/users/{user_id}",
    response_model=UserResponse,
    dependencies=[Security(get_current_user_with_scope_check, scopes=["delete:users"])],
)
def delete_user(session: SessionDep, user_id: int):
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    session.delete(user)
    session.commit()

    return user


app.include_router(admin_router)
app.include_router(user_router)
