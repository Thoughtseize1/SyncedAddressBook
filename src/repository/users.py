from libgravatar import Gravatar  # poetry add libgravatar
from sqlalchemy.orm import Session

from src.database.models import User
from src.schemas import UserModel


async def get_user_by_email(email: str, db: Session) -> User:
    """Приймає email та сеанс бази даних db та повертає об'єкт користувача з бази даних,
    якщо він існує з такою адресою електронної пошти."""
    return db.query(User).filter(User.email == email).first()


async def create_user(body: UserModel, db: Session) -> User:
    """Приймає параметр body, який вже пройшов валідацію моделлю користувача UserModel з тіла запиту,
    та другий параметр - сеанс бази даних db. Створює нового користувача у базі даних, 
    а потім повертає щойно створений об'єкт User."""
    avatar = None
    try:
        g = Gravatar(body.email)  # об'єкт створює на основі електронної пошти
        avatar = g.get_image()  # отримує URL-адресу аватара з Gravatar API
    except Exception as e:
        print(e)
    new_user = User(**body.model_dump(), avatar=avatar)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


async def update_token(user: User, token: str | None, db: Session) -> None:
    """Приймає об'єкт користувача user, токен оновлення token та сеанс бази даних db.
    Вона оновлює поле refresh_token користувача та фіксує зміни у базі даних."""
    user.refresh_token = token
    db.commit()
