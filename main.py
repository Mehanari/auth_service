from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
from typing import Optional
from jose import JWTError, jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Configurations
SECRET_KEY = "your_secret_key_here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
DATABASE_URL = "mysql+pymysql://root:root@localhost/auth_service"

# SQLAlchemy setup
Base = declarative_base()
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class UserModel(Base):
    __tablename__ = "service_user"
    id = Column(Integer, primary_key=True, index=True)
    login = Column(String(250), unique=True, index=True, nullable=False)
    password = Column(String(250), nullable=False)


Base.metadata.create_all(bind=engine)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# FastAPI app
app = FastAPI()


class User(BaseModel):
    login: str
    password: str


class Token(BaseModel):
    token: str


@app.post("/auth", response_model=Token)
def register_or_login(user: User):
    db = SessionLocal()
    stored_user = db.query(UserModel).filter(UserModel.login == user.login).first()
    if stored_user:
        # Login flow
        if not verify_password(user.password, stored_user.password):
            db.close()
            raise HTTPException(status_code=401, detail="Invalid credentials")
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.login}, expires_delta=access_token_expires
        )
        db.close()
        return {"token": access_token}
    else:
        # Registration flow
        hashed_password = get_password_hash(user.password)
        new_user = UserModel(login=user.login, password=hashed_password)
        db.add(new_user)
        db.commit()
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.login}, expires_delta=access_token_expires
        )
        db.close()
        return {"token": access_token}


@app.get("/exchange-token")
def exchange_token(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Token missing")
    try:
        token = authorization.split(" ")[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        login = payload.get("sub")
        if login is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        db = SessionLocal()
        user = db.query(UserModel).filter(UserModel.login == login).first()
        db.close()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")
        return {"userId": user.id}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.post("/logout")
def logout(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Token missing")
    # Logout implementation (if token invalidation is required, add token tracking in DB)
    return {"message": "Logged out successfully"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=8001)
