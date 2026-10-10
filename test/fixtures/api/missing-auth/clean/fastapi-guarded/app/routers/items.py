from fastapi import APIRouter, Depends

from app.deps import get_current_user

router = APIRouter(prefix="/items", dependencies=[Depends(get_current_user)])


@router.get("/{item_id}")
def read_item(item_id: int):
    return {"id": item_id}
