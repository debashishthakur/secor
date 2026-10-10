from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Note(Base):
    __tablename__ = "notes"
    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id"))
    body = Column(String)
