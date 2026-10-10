from pydantic import BaseModel


class UserBase(BaseModel):
    email: str


class UserCreate(UserBase):
    password: str
    is_admin: bool = False


class UserUpdate(BaseModel):
    email: str | None = None
    role: str | None = None
