from fastapi import Depends, FastAPI, Request
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Item, Tag
from app.schemas import ItemCreate, TagCreate

app = FastAPI()


@app.post("/items")
def create_item(payload: ItemCreate, db: Session = Depends(get_db)):
    item = Item(**payload.model_dump())
    db.add(item)
    db.commit()
    return {"id": item.id}


@app.post("/tags")
async def create_tag(request: Request, db: Session = Depends(get_db)):
    tag = TagCreate.model_validate(await request.json())
    db.add(Tag(name=tag.name))
    db.commit()
    return {"ok": True}
