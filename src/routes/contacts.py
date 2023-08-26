from typing import List, Optional

from fastapi import APIRouter, Query, Depends, Path, status, HTTPException
from sqlalchemy.orm import Session

from src.database.db import get_db
from src.database.models import Contact, User
from src.schemas import ContactResponse, ContactModel, ContactBirthdaysResponse, ContactSearchResponse
from src.repository import contacts as repository_contacts
from src.services.auth import auth_service

router = APIRouter(prefix='/contacts', tags=['Contacts'])


@router.get('/', name='Get all contacts', response_model=List[ContactResponse])
async def get_all_contacts(limit: int = Query(default=10, le=200),
                           db: Session = Depends(get_db), current_user: User = Depends(auth_service.get_current_user)):
    contacts = await repository_contacts.get_contacts(current_user, db, limit)
    return contacts


@router.get('/{contact_id}', name="Get one contact", response_model=ContactResponse)
async def get_contact(contact_id: int = Path(ge=1), db: Session = Depends(get_db),
                      current_user: User = Depends(auth_service.get_current_user)):
    contact = await repository_contacts.get_contact(contact_id, current_user, db)
    if contact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="CONTACT NOT FOUND")
    return contact


@router.post('/', name="Create new contact", response_model=ContactResponse, status_code=status.HTTP_201_CREATED)
async def create_contact(body: ContactModel, db: Session = Depends(get_db),
                         current_user: User = Depends(auth_service.get_current_user)):
    return await repository_contacts.create_contact(body, current_user, db)


@router.put('/{contact_id}', name="Change contact", response_model=ContactResponse)
async def change_contact(body: ContactModel, contact_id: int = Path(ge=1), db: Session = Depends(get_db),
                         current_user: User = Depends(auth_service.get_current_user)):
    contact = await repository_contacts.update_contact(contact_id, body, current_user, db)
    if contact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="NOT FOUND")
    return contact


@router.get('/search/', response_model=List[ContactSearchResponse])
async def search_contacts(
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        email: Optional[str] = None,
        db: Session = Depends(get_db),
        current_user: User = Depends(auth_service.get_current_user)
):
    searched_contacts = await repository_contacts.search_by_some_data(current_user, db, first_name, last_name, email)
    return searched_contacts


@router.delete('/{contact_id}', name='Delete one contact', status_code=status.HTTP_204_NO_CONTENT)
async def delete_contact(
        contact_id: int = Path(ge=1),
        db: Session = Depends(get_db),
        current_user: User = Depends(auth_service.get_current_user)
):
    deleted_contact = await repository_contacts.remove_contact(contact_id, current_user, db)
    if not deleted_contact:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contact not found")


@router.get("/birthdays/", response_model=List[ContactBirthdaysResponse])
async def get_upcoming_birthdays(db: Session = Depends(get_db),
                                 current_user: User = Depends(auth_service.get_current_user)):
    contacts = await repository_contacts.search_birthdays(current_user, db)
    return contacts
