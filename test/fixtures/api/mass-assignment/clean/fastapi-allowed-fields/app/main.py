from fastapi import Depends, FastAPI
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Item, User
from app.schemas import ItemCreate, UserUpdate

app = FastAPI()


@app.post("/items")
def create_item(payload: ItemCreate, db: Session = Depends(get_db)):
    item = Item(**payload.model_dump())
    db.add(item)
    db.commit()
    return {"id": item.id}


@app.patch("/users/{user_id}")
def update_user(user_id: int, payload: UserUpdate, db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    for key, value in payload.model_dump(exclude={"role"}, exclude_unset=True).items():
        setattr(user, key, value)
    db.add(user)
    db.commit()
    return {"id": user.id}
