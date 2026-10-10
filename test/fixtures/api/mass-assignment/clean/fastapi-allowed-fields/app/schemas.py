from pydantic import BaseModel


class ItemCreate(BaseModel):
    name: str


class UserUpdate(BaseModel):
    email: str | None = None
    role: str | None = None
