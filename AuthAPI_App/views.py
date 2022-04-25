from concurrent.futures import process
from datetime import datetime
from lib2to3.pgen2 import token
from logging import exception
from urllib import response
from click import password_option
from django.http import HttpRequest
from django.shortcuts import render
from httplib2 import Authentication
from rest_framework.views import APIView
# from .serializers import UserSerializer
from rest_framework.response import Response
# from django.contrib.auth.models import User
from .models import User
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.hashers import make_password, check_password
import jwt, datetime
import json
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.decorators import authentication_classes, permission_classes
from OAuth import settings

# Create your views here.
class RegisterView(APIView):
    def post(self, request):
        email = request.data['email']
        username = request.data['username']
        password = make_password(request.data['password'])
        User(email, username, password).save()
        return Response((
            request.data
        ))

class LoginView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']

        user = User.objects.raw({'_id':email}).first()
        if user is None:
            raise exception()
            
        if not check_password(password, user.password):
            raise exception()

        payload = {
            'id': user.email,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow()
        }

        # token = jwt.encode(payload, 'secret', algorithm='HS256').decode('utf-8')
        token = jwt.encode(payload, settings.SECRET_KEY)
        response = Response()

        response.data = {
            'jwt': token
        }

        return response


class UserView(APIView):
    def get(self, request):
        token = request.headers
        payload = jwt.decode(token['Authorization'], settings.SECRET_KEY)
        user = User.objects.raw({'_id':payload['id']}).first()
        return Response({
            "email":user.email,
            "username":user.username
        })


class LogoutView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            'message': 'Logged out successfully'
        }

        return response