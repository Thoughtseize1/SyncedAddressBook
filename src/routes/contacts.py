from datetime import date, timedelta, datetime
from typing import List, Optional

from fastapi import APIRouter, Query, Depends, Path, status, HTTPException
from sqlalchemy import func, or_, text
from sqlalchemy.orm import Session

from src.database.db import get_db
from src.database.models import Contact
from src.schemas import ContactResponse, ContactModel, ContactBirthdaysResponse, ContactSearchResponse

router = APIRouter(prefix='/contacts', tags=['Contacts'])


@router.get('/', name='Get all contacts', response_model=List[ContactResponse])
async def get_all_contacts(limit: int = Query(default=10, le=200), offset: int = Query(default=0, le=100),
                           db: Session = Depends(get_db)):
    contacts = db.query(Contact).limit(limit).offset(offset).all()
    return contacts


@router.get('/{contact_id}', name="Get one contact", response_model=ContactResponse)
async def get_contact(contact_id: int = Path(ge=1), db: Session = Depends(get_db)):
    contact = db.get(Contact, contact_id)
    if contact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="CONTACT NOT FOUND")
    return contact


@router.post('/', name="Create new contact", response_model=ContactResponse)
async def create_contact(body: ContactModel, db: Session = Depends(get_db)):
    contact = Contact(**body.model_dump())
    db.add(contact)
    db.commit()
    print('Contact created successfully')
    return contact


@router.put('/{contact_id}', name="Change contact", response_model=ContactResponse)
async def change_contact(body: ContactModel, contact_id: int = Path(ge=1), db: Session = Depends(get_db)):
    contact = db.get(Contact, contact_id)
    if contact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="NOT FOUND")
    contact.first_name = body.first_name
    contact.last_name = body.last_name
    contact.email = body.email
    contact.phone_number = body.phone_number
    contact.birthdate = body.birthdate
    contact.additional_data = body.additional_data
    db.commit()
    return contact


@router.get('/search/', response_model=List[ContactSearchResponse])
async def search_contacts(
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        email: Optional[str] = None,
        db: Session = Depends(get_db)
):
    if first_name:
        query = db.query(Contact).filter(Contact.first_name.ilike(f"%{first_name}%"))

    if last_name:
        query = db.query(Contact).filter(Contact.last_name.ilike(f"%{last_name}%"))

    if email:
        query = db.query(Contact).filter(Contact.email.ilike(f"%{email}%"))

    contacts = query.all()
    if not contacts:
        raise HTTPException(status_code=status.HTTP_204_NO_CONTENT, headers={'details': 'NOT FOUND'})
    return contacts


@router.delete('/{contact_id}', name='Delete one contact', status_code=status.HTTP_204_NO_CONTENT)
async def delete_contact(contact_id: int = Path(ge=1), db: Session = Depends(get_db)):
    contact = db.query(Contact).filter_by(id=contact_id).first()
    if contact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="NOT FOUND")
    db.delete(contact)
    db.commit()
    print(f'Contact {contact.first_name} deleted')


@router.get("/birthdays/", response_model=List[ContactBirthdaysResponse])
def get_upcoming_birthdays(db: Session = Depends(get_db)):
    today = date.today()
    seven_days_later = today + timedelta(days=7)

    upcoming_birthdays = (
        db.query(Contact)
        .filter(
            or_(
                (func.date_part('month', Contact.birthdate) == today.month) & (
                            func.date_part('day', Contact.birthdate) >= today.day),
                (func.date_part('month', Contact.birthdate) == seven_days_later.month) & (
                            func.date_part('day', Contact.birthdate) <= seven_days_later.day)
            )
        )
        .all()
    )

    db.close()
    return upcoming_birthdays
