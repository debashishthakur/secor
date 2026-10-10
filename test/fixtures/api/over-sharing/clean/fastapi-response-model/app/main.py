from fastapi import Depends, FastAPI
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import User
from app.schemas import UserOut

app = FastAPI()


@app.get("/users/{user_id}", response_model=UserOut)
def read_user(user_id: int, db: Session = Depends(get_db)):
    return db.get(User, user_id)


@app.get("/users")
def list_users(db: Session = Depends(get_db)) -> list[UserOut]:
    return db.query(User).all()


@app.get("/emails")
def list_emails(db: Session = Depends(get_db)):
    return db.query(User.id, User.email).all()
