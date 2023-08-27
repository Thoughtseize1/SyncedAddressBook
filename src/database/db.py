from fastapi import HTTPException, status
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError

from src.conf.config import settings

DATABASE_URL = settings.sqlalchemy_database_url
engine = create_engine(DATABASE_URL, echo=False)
DBSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# Dependency
def get_db():
    db = DBSession()
    try:
        yield db
    except SQLAlchemyError as err:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err))
    finally:
        db.close()