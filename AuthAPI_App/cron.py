from .models import Desktop_token, Mobile_token
import jwt
from OAuth import settings


def desktop_token_remover():
    for user in Desktop_token.objects.all():
        try:
            jwt.decode(user.access_token[2:-1], settings.SECRET_KEY)
        except:
            try:
                jwt.decode(user.refresh_token[2:-1], settings.REFRESH_KEY)
            except:
                user.delete()


def mobile_token_remover():
    for user in Mobile_token.objects.all():
        try:
            jwt.decode(user.access_token[2:-1], settings.SECRET_KEY)
        except:
            try:
                jwt.decode(user.refresh_token[2:-1], settings.REFRESH_KEY)
            except:
                user.delete()