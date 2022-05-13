from .token_generator import decode_access_token
from .models import User
from bson import ObjectId
import json
from django.http import JsonResponse
from rest_framework.response import Response


def get_terms_query(list_of_ids):
    return {
        "query": {
            "terms": {
                "id": list_of_ids
            }
        }
    }

def get_user(request):
    token = request.headers
    if 'Authorization' in token:
        payload = decode_access_token(token)
        user = User.objects.raw({'_id':ObjectId(payload['id'])}).first()
        return user
    else:
        email = request.data['email']
        password = request.data['password']
        try:
            user = User.objects.raw({'email':email}).first()
        except:
            return JsonResponse({
                "message": "Email not found"
            }, status=401)
        return user