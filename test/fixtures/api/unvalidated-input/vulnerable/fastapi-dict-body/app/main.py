from fastapi import Depends, FastAPI, Request
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Item, Tag

app = FastAPI()


@app.post("/items")
async def create_item(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    item = Item(**data)
    db.add(item)
    db.commit()
    return {"id": item.id}


@app.post("/tags")
def create_tag(payload: dict, db: Session = Depends(get_db)):
    db.add(Tag(name=payload["name"]))
    db.commit()
    return {"ok": True}
