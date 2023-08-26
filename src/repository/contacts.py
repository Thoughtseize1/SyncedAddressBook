from src.schemas import ContactResponse, ContactModel, ContactBirthdaysResponse
from src.services.auth import auth_service

# функції для взаємодії з базою даних.
from datetime import date, timedelta
from typing import Optional, List

from fastapi import HTTPException, status
from fastapi.encoders import jsonable_encoder
from sqlalchemy import cast, func, or_, String, select, extract, and_, asc
from sqlalchemy.orm import Session

from src.database.models import Contact, User


async def get_contacts(
        user: User,
        db: Session,
        limit
) -> List[ContactResponse]:
    """To retrieve a list of records from a database with the ability to skip 
    a certain number of records and limit the number returned."""
    user_contacts = db.query(Contact).filter(Contact.user_id == user.id).order_by(Contact.first_name).limit(limit).all()
    return user_contacts


async def get_contact(
        contact_id: int,
        user: User,
        db: Session
) -> Optional[Contact]:
    """To get a particular record by its ID."""
    user_contact = db.query(Contact).filter(Contact.user_id == user.id).filter_by(id=contact_id).first()
    return user_contact


async def create_contact(
        body: ContactModel,
        user: User,
        db: Session
) -> Contact:
    """Creating a new record in the database. Takes a ContactModel object and uses the information
    from it to create a new Contact object, then adds it to the session and
    commits the changes to the database."""
    contact = (db.query(Contact).filter(Contact.user_id == user.id).filter_by(email=body.email).first() or
               db.query(Contact).filter(Contact.user_id == user.id).filter_by(phone_number=body.phone_number).first() or
               db.query(Contact).filter(Contact.user_id == user.id).filter_by(first_name=body.first_name,
                                                                              last_name=body.last_name).first())
    if contact:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail='Duplicate data')

    contact = Contact(**body.model_dump(), user_id=user.id)
    db.add(contact)
    db.commit()
    return contact


async def update_contact(
        contact_id: int,
        body: ContactModel,
        user: User,
        db: Session
) -> Contact:
    """Update a specific record by its ID. Takes the ContactModel object and updates the information from it
    by the name of the record. If the record does not exist - None is returned."""
    contact: Contact = db.query(Contact).filter(Contact.user_id == user.id).filter_by(id=contact_id).first()
    if contact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contact not found")
    db_obj_data = jsonable_encoder(contact)
    body_data = jsonable_encoder(body)
    for field in db_obj_data:
        if field in body_data:
            setattr(contact, field, body_data[field])
    db.commit()
    db.refresh(contact)
    return contact


async def remove_contact(
        contact_id: int,
        user: User,
        db: Session
) -> Optional[Contact]:
    """Delete a specific record by its ID. If the record does not exist - None is returned."""
    contact = db.query(Contact).filter(Contact.user_id == user.id).filter_by(id=contact_id).first()
    if contact:
        db.delete(contact)
        db.commit()
    return contact


async def search_birthdays(
        user: User,
        db: Session
) -> List[ContactBirthdaysResponse]:
    """To find contacts celebrating birthdays in the next (meantime) days."""
    today = date.today()
    end_date = today + timedelta(days=7)

    stmt = (
        select(Contact)
        .where(
            and_(
                Contact.user_id == user.id,
                or_(
                    and_(
                        extract('month', Contact.birthdate) == today.month,
                        extract('day', Contact.birthdate) >= today.day
                    ),
                    and_(
                        extract('month', Contact.birthdate) == end_date.month,
                        extract('day', Contact.birthdate) <= end_date.day
                    )
                )
            )
        )
    ).order_by(asc(Contact.id))
    result = db.execute(stmt)
    return result.scalars().all()


async def search_by_some_data(user: User, db: Session, first_name, last_name, email):
    if first_name:
        query = db.query(Contact).filter(Contact.user_id == user.id).filter(Contact.first_name.ilike(f"%{first_name}%"))

    if last_name:
        query = db.query(Contact).filter(Contact.user_id == user.id).filter(Contact.last_name.ilike(f"%{last_name}%"))

    if email:
        query = db.query(Contact).filter(Contact.user_id == user.id).filter(Contact.email.ilike(f"%{email}%"))

    contacts = query.all()
    if not contacts:
        raise HTTPException(status_code=status.HTTP_204_NO_CONTENT, headers={'details': 'NOT FOUND'})
    return contacts
