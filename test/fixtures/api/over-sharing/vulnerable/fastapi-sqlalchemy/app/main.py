from fastapi import Depends, FastAPI
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import User

app = FastAPI()


@app.get("/users/{user_id}")
def read_user(user_id: int, db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    return user


@app.get("/users")
def list_users(db: Session = Depends(get_db)):
    return db.query(User).all()
