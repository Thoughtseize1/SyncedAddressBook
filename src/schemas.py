from typing import Optional

from fastapi import HTTPException, status
from pydantic import BaseModel, EmailStr, Field, field_validator
from datetime import date, datetime


class ContactModel(BaseModel):
    first_name: str = Field('Sheldon', min_length=2, max_length=25)
    last_name: str = Field('Cooper', min_length=3, max_length=25)
    email: EmailStr = Field('superCat@ukr.net', min_length=3, max_length=25)
    phone_number: str = Field('+380997184714', min_length=8, max_length=25)
    birthdate: Optional[date] = Field(description='Birthdate in the format YYYY-MM-DD (optional)')
    additional_data: str = Field('Note for contact', max_length=200)


class ContactResponse(BaseModel):
    id: int = 1
    first_name: str
    last_name: str
    email: EmailStr
    phone_number: str
    birthdate: date
    additional_data: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes: True


class ContactSearchResponse(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone_number: str
    birthdate: date
    additional_data: str

    class Config:
        from_attributes: True


class ContactBirthdaysResponse(BaseModel):
    first_name: str
    birthdate: date
