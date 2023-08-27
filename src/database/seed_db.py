import random

from sqlalchemy.orm import Session
from faker import Faker
from src.database.models import Contact
from src.database.db import get_db

fake = Faker('uk_UA')


def create_fake_contact():
    return Contact(
        first_name=fake.first_name(),
        last_name=fake.last_name(),
        email=fake.email(),
        phone_number=fake.phone_number(),
        birthdate=fake.date_of_birth(),
        additional_data = fake.sentence(),
    )


def seed_contacts(num_contacts: int, db: Session):
    contacts = [create_fake_contact() for _ in range(num_contacts)]
    db.add_all(contacts)
    db.commit()


def main():
    db = next(get_db())
    num_contacts = 10
    seed_contacts(num_contacts, db)
    db.close()


if __name__ == "__main__":
    main()