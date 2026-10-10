from fastapi import Depends, FastAPI
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db

app = FastAPI()


@app.get("/users")
def find_users(name: str, db: Session = Depends(get_db)):
    rows = db.execute(text(f"SELECT * FROM users WHERE name = '{name}'")).fetchall()
    return [dict(r._mapping) for r in rows]


def legacy_lookup(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
    cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    cursor.execute(query)
    return cursor.fetchall()
