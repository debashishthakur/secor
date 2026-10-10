from typing import Annotated
from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_current_user(token: str = Depends(oauth2_scheme)):
    return {"id": 1}

CurrentUser = Annotated[dict, Depends(get_current_user)]
