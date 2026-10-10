from fastapi import Depends, FastAPI
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db

app = FastAPI()


@app.get("/users")
def find_users(name: str, db: Session = Depends(get_db)):
    rows = db.execute(text("SELECT * FROM users WHERE name = :name"), {"name": name}).fetchall()
    return [dict(r._mapping) for r in rows]


def legacy_lookup(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    cursor.executemany("INSERT INTO audit (user_id) VALUES (%s)", [(user_id,)])
    return cursor.fetchall()
