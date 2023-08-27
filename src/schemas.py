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
    additional_data: Optional[str] = None
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
    additional_data: Optional[str] = None

    class Config:
        from_attributes: True


class DeletedContactResponse(BaseModel):
    """модель відповіді, яка містить у собі модель UserDb та поле відомостей detail з рядком."""
    first_name: str
    detail: str = "Contact successfully deleted"


class ContactBirthdaysResponse(BaseModel):
    first_name: str
    birthdate: date


class UserModel(BaseModel):
    """корисні дані запиту для створення нового користувача."""
    username: str = Field(min_length=2, max_length=30)
    email: EmailStr = Field('superUser@ukr.net', min_length=3, max_length=25)
    password: str = Field(min_length=6, max_length=10)


class UserFromDb(BaseModel):
    """визначає представлення бази даних користувача."""
    id: int
    username: str
    email: str
    created_at: datetime
    avatar: str

    class Config:
        """вказує, що модель UserDb використовується для представлення моделі ORM."""
        from_attributes = True


class UserResponse(BaseModel):
    """модель відповіді, яка містить у собі модель UserDb та поле відомостей detail з рядком."""
    user: UserFromDb
    detail: str = "User successfully created"


class TokenModel(BaseModel):
    """визначає відповідь при отриманні токенів доступу для користувача, що пройшов аутентифікацію."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RequestEmail(BaseModel):
    email: EmailStr

class EmailSchema(BaseModel):
    email: EmailStr