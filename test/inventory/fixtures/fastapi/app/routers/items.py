from fastapi import APIRouter, Depends
from app.api.deps import CurrentUser, oauth2_scheme

router = APIRouter(prefix="/items")

@router.get("/")
def list_items():
    return []

@router.get("/{item_id}")
def get_item(item_id: int, user: CurrentUser):
    return {"id": item_id}

@router.api_route("/{item_id}/tags", methods=["GET", "PUT"], dependencies=[Depends(oauth2_scheme)])
def tags(item_id: int):
    return []
