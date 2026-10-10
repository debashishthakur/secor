from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session

from app.deps import CurrentUser, SessionDep, get_current_user, get_db
from app.models import Note

app = FastAPI()


@app.get("/notes/{note_id}")
def read_note(note_id: int, db: Session = Depends(get_db), user: dict = Depends(get_current_user)):
    note = db.get(Note, note_id)
    if note is None:
        raise HTTPException(status_code=404)
    return note


@app.delete("/notes/{note_id}")
def delete_note(note_id: int, db: SessionDep, user: CurrentUser):
    db.query(Note).filter(Note.id == note_id).delete()
    db.commit()


@app.get("/legacy/notes/{note_id}")
def read_note_legacy(note_id: int, db: SessionDep, user: CurrentUser):
    return db.query(Note).get(note_id)
