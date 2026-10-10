from typing import Annotated

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_db():
    yield None


def get_current_user(token: str = Depends(oauth2_scheme)):
    return token


CurrentUser = Annotated[dict, Depends(get_current_user)]
SessionDep = Annotated[Session, Depends(get_db)]
