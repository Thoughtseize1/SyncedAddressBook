from sqlalchemy import Column, Integer, String, Date, DateTime, func
from sqlalchemy.orm import declarative_base

"""
Контакти повинні зберігатися в базі даних та містити в собі наступну інформацію:

Ім'я
Прізвище
Електронна адреса
Номер телефону
День народження
Додаткові дані (необов'язково)

"""
Base = declarative_base()


class Contact(Base):
    __tablename__ = "contacts"
    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String, index=True)
    last_name = Column(String)
    email = Column(String, unique=True, index=True)
    phone_number = Column(String, index=True)
    birthdate = Column(Date, nullable=True)
    additional_data = Column(String, nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())