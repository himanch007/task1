from OAuth import settings
from .models import User
import jwt, datetime
import json


def get_access_token(user):
    payload = {
            'id': str(user._id),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
            'iat': datetime.datetime.utcnow()
        }
    return jwt.encode(payload, settings.SECRET_KEY)

def get_refresh_token(user):
    refresh_payload = {
            'id': str(user._id),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow()
        }
    return jwt.encode(refresh_payload, settings.REFRESH_KEY)

def decode_access_token(token):
    return jwt.decode(token['Authorization'], settings.SECRET_KEY)

def decode_refresh_token(token):
    return jwt.decode(token['Authorization'], settings.REFRESH_KEY)