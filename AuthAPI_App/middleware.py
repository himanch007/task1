from email import message
from logging import exception
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponse
import jwt
from .models import User, Desktop_token, Mobile_token
from OAuth import settings
from rest_framework.response import Response
from rest_framework import status
from django.http import JsonResponse
from django.urls import (get_resolver, get_urlconf, resolve, reverse, NoReverseMatch)
from bson import ObjectId


class MyMiddleware:
    def __init__(self, get_response):  
        self.get_response = get_response

    def __call__(self, request):
        # print(vars(request))
        # print(request.body)
        NO_AUTHORIZATION_REQUIRED_URLS = ['api/register', 'api/login', 'api/refresh-token']
        if resolve(request.path).route not in NO_AUTHORIZATION_REQUIRED_URLS:
            token = request.headers
            try:
                payload = jwt.decode(token['Authorization'], settings.SECRET_KEY)
                token = request.headers
                access_token = "b'"+token['Authorization']+"'"
                if(token['Device'] == 'Desktop'):
                    Desktop_token.objects.raw({'access_token':access_token}).first()
                elif(token['Device'] == 'Mobile'):
                    Mobile_token.objects.raw({'access_token':access_token}).first()
                else:
                    return JsonResponse({
                        'message': 'Device not found'
                    })
            except:
                return JsonResponse({
                    'message': 'Not a valid token'
                    }, status=401)
        response = self.get_response(request)
        return response

    # def process_exception(self, request, exception):
    #     return JsonResponse({
    #         'message':'Invalid credentials'
    #     }, status=401)