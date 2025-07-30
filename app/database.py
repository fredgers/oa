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

print(key.thumbprint())

# https://blog.stackademic.com/using-fastapi-with-sqlalchemy-5cd370473fe5

# from sqlalchemy import create_engine, Column, Integer, String
# from sqlalchemy.orm import sessionmaker
# from sqlalchemy.ext.declarative import declarative_base

# SQLALCHEMY_DATABASE_URL = "postgresql://user:password@localhost/dbname"

# engine = create_engine(SQLALCHEMY_DATABASE_URL)
# SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
# Base = declarative_base()

# def get_db():
#     db = SessionLocal()
#     try:
#         yield db
#     finally:
#         db.close()
