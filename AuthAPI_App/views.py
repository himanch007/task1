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
from rest_framework.response import Response
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
from .token_generator import get_access_token, get_refresh_token, decode_access_token, decode_refresh_token
from django.http import JsonResponse
from bson import ObjectId


# Create your views here.
class RegisterView(APIView):
    def post(self, request):
        email = request.data['email']
        username = request.data['username']
        password = make_password(request.data['password'])

        try:
            user = User.objects.raw({'email':email}).first()
            return JsonResponse({
                    "message": "This email already exists"
                }, status=409)
        except:
            if not email:
                return JsonResponse({
                    "message": "email is required"
                }, status=401)

            if not username:
                return JsonResponse({
                    "message": "username is required"
                }, status=401)
            
            if not request.data['password']:
                return JsonResponse({
                    "message": "password is required"
                }, status=401)

            User(email, username, password).save()
            return Response({
                "email": email,
                "username": username
            }, status=201)

class LoginView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']
        try:
            user = User.objects.raw({'email':email}).first()
        except:
            return JsonResponse({
                "message": "Email not found"
            }, status=401)
            
        if not check_password(password, user.password):
            return JsonResponse({
                "message": "Incorrect password"
            }, status=401)
        
        access_token = get_access_token(user)
        print(access_token)
        refresh_token = get_refresh_token(user)
        response = Response()

        response.data = {
            'access_token': access_token,
            'refresh_token': refresh_token
        }

        return response


class UserView(APIView):
    def get(self, request):
        token = request.headers
        payload = decode_access_token(token)
        user = User.objects.raw({'_id':ObjectId(payload['id'])}).first()
        return Response({
            "email":user.email,
            "username":user.username
        })


class RefreshTokenView(APIView):
    def post(self, request):
        token = request.headers
        payload = decode_refresh_token(token)
        user = User.objects.raw({'_id':ObjectId(payload['id'])}).first()
        new_access_token = get_access_token(user)
        response = Response()

        response.data = {
            'access_token': new_access_token
        }
        
        return response

class LogoutView(APIView):
    def post(self, request):
        # access_token = request.data['access_token']
        # refresh_token = request.data['refresh_token']
        # decoded_access_token = decode_access_token(access_token)
        # decoded_access_token['exp'] = datetime.datetime.utcnow()
        response = Response()
        response.data = {
            'message': 'Logged out successfully'
        }

        return response