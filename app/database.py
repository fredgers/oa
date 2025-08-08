import redis

def create_redis():
  return redis.ConnectionPool(
    host='localhost', 
    port=6379, 
    db=0, 
    decode_responses=True
  )

redis_pool = create_redis()

import tomllib

with open("oadb.toml", "rb") as f:
    oadb = tomllib.load(f)

from jwcrypto import jwk

f = open("key.pem","rb")
k = f.read()
key = jwk.JWK.from_pem(k, password=None)
keys = jwk.JWKSet()
keys.add(key)

# https://blog.stackademic.com/using-fastapi-with-sqlalchemy-5cd370473fe5

# from sqlalchemy import create_engine, Column, Integer, String
# from sqlalchemy.orm import sessionmaker
import sqlalchemy as sa

from sqlalchemy.orm import sessionmaker, DeclarativeBase, Mapped, mapped_column
import uuid

SQLALCHEMY_DATABASE_URL = "postgresql://oidc:xMBuF2gKvyqBev8t@192.168.1.6/oidc"

engine = sa.create_engine(SQLALCHEMY_DATABASE_URL, echo=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# from pydantic import BaseModel

# class ItemBase(BaseModel):
#     name: str
#     description: str
# class ItemCreate(ItemBase):
#     pass
# class Item(ItemBase):
#     id: uuid.UUID

#     class Config:
#         orm_mode = True

metadata_obj = sa.MetaData(schema="oa")

class Base(DeclarativeBase):
  metadata = metadata_obj

class User(Base):
  __tablename__ = "users"
  id: Mapped[uuid.UUID | None] = mapped_column(primary_key=True, default=uuid.uuid4)
  email: Mapped[str | None]
  password: Mapped[str | None]
  first_name: Mapped[str | None]
  last_name: Mapped[str | None]

# u = User(email="c", password="c", first_name="ger", last_name="rso")
# print(u)
# db_gen = get_db()
# db = next(db_gen)
# db.add_all([u])

# db.commit()

# for class_instance in db.query(User).all():
#     print(vars(class_instance))
