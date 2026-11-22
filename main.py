import secrets
from contextlib import asynccontextmanager
from datetime import UTC, timedelta
from typing import Annotated

from fastapi import APIRouter, Body, Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import select

from database import SessionDep, create_db_and_tables
from models import (
    PasswordResteToken,
    PasswordRestRequest,
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

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield


invalid_token_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid token",
    headers={"WWW-Authenticate": "Bearer"},
)
app = FastAPI(lifespan=lifespan)


def get_current_user(
    session: SessionDep, token: Annotated[str, Depends(oauth2_scheme)]
):
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


CurrentUser = Annotated[User, Depends(get_current_user)]


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


@app.post("/token", status_code=status.HTTP_200_OK)
def login(
    session: SessionDep, form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    existing_user = session.exec(
        select(User).where(User.email == form_data.username)
    ).first()

    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not existing_user:
        # Deceive hacker with timimg needed to hash the password
        verify_password(form_data.password, DUMMY_HASH)
        raise credential_exception

    if not verify_password(form_data.password, existing_user.hashed_password):
        raise credential_exception

    data = {"sub": existing_user.email}

    access_token = create_access_token(data=data)
    refresh_token = create_refresh_token(data=data)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@app.post("/token/refresh")
def refresh_token(session: SessionDep, refresh_token: Annotated[str, Body(embed=True)]):
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
    return {
        "access_token": new_access_token,
        "token_type": "bearer",
    }


user_router = APIRouter(tags=["users"], dependencies=[Depends(get_current_user)])


@user_router.get("/me", status_code=status.HTTP_200_OK, response_model=UserResponse)
def get_me(current_user: CurrentUser):
    return current_user


@user_router.patch("/me", status_code=status.HTTP_200_OK, response_model=UserResponse)
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
    return {"profit": 1000000}


app.include_router(user_router)


@app.post("/passwor-reset/request")
def requeest_password_reset(session: SessionDep, payload: PasswordRestRequest):
    messsage = {"message": "If exists, reset email sent."}

    user = session.exec(select(User).where(User.email == payload.email)).first()

    if not user or not user.id:
        return messsage

    token = secrets.token_urlsafe(32)

    reset_token = PasswordResteToken(
        token=token,
        user_id=user.id,
        expires_at=dashboard.now(UTC) + timedelta(minutes=10),
        used=False,
    )

    session.add(reset_token)
    session.commit()

    return messsage
