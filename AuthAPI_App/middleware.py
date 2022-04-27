from email import message
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponse
import jwt
from .models import User
from OAuth import settings
from rest_framework.response import Response
from rest_framework import status
from django.http import JsonResponse
from django.urls import (get_resolver, get_urlconf, resolve, reverse, NoReverseMatch)


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
                jwt.decode(token['Authorization'], settings.SECRET_KEY)
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