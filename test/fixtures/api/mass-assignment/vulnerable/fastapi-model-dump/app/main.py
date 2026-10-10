from fastapi import Depends, FastAPI
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import User
from app.schemas import UserCreate, UserUpdate

app = FastAPI()


@app.post("/users")
def create_user(payload: UserCreate, db: Session = Depends(get_db)):
    user = User(**payload.dict())
    db.add(user)
    db.commit()
    return {"id": user.id}


@app.patch("/users/{user_id}")
def update_user(user_id: int, payload: UserUpdate, db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(user, key, value)
    db.add(user)
    db.commit()
    return {"id": user.id}
