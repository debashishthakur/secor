from pydantic import BaseModel


class ItemCreate(BaseModel):
    name: str


class TagCreate(BaseModel):
    name: str
