import jwt
from fastapi import HTTPException
from passlib.context import CryptContext
from datetime import datetime, timedelta
from decouple import config

JWT_KEY = config('JWT_KEY')

class AuthJwtCsrf():
    pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
    secret_key = JWT_KEY

    def generate_hashed_pw(self, password) -> str:
        return self.pwd_ctx.hash(password)

    def verify_pw(self, plain_pw, hashed_pw) -> bool:
        return self.pwd_ctx.verify(plain_pw, hashed_pw)

    def (variable) payload: dict[str, Any]
        payload = {
            'exp': datetime.utcnow() + timedelta(days=0, minutes=5),
            'iat': datetime.utcnow(),
            'sub': email
        }
        return jwt.encode(
            payload,
            self.secret_key,
            algorithm='HS256'
        )
