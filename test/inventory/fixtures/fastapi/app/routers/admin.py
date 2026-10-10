from fastapi import APIRouter, Depends
from app.api.deps import get_current_user

router = APIRouter(prefix="/admin", dependencies=[Depends(get_current_user)])

@router.delete("/users/{user_id}")
def delete_user(user_id: int):
    return None
