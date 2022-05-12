from concurrent.futures import process
from datetime import datetime
from lib2to3.pgen2 import token
from logging import exception
from urllib import response
from click import password_option
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
import elasticsearch
from httplib2 import Authentication
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import User, Desktop_token, Mobile_token
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
import requests
from .tasks import add


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
        refresh_token = get_refresh_token(user)

        token = request.headers
        if(token['Device'] == 'Desktop'):
            Desktop_token(user._id, access_token, refresh_token).save()
        elif(token['Device'] == 'Mobile'):
            Mobile_token(user._id, access_token, refresh_token).save()
        else:
            return JsonResponse({
                'message': 'Device name not found'
            })

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
        refresh_token = "b'"+token['Authorization']+"'"
        try:
            if(token['Device'] == 'Desktop'):
                user = Desktop_token.objects.raw({'refresh_token':refresh_token}).first()
                decode_refresh_token(token)
            elif(token['Device'] == 'Mobile'):
                user = Mobile_token.objects.raw({'refresh_token':refresh_token}).first()
                decode_refresh_token(token)
            else:
                return JsonResponse({
                    'message': 'Device not found'
                })
        except:
            return JsonResponse({
                "message": "Token expired"
            }, status=401)
        payload = decode_refresh_token(token)
        user = User.objects.raw({'_id':ObjectId(payload['id'])}).first()
        new_access_token = get_access_token(user)

        if(token['Device'] == 'Desktop'):
            Desktop_token(user._id, new_access_token, "null").save()
        elif(token['Device'] == 'Mobile'):
            Mobile_token(user._id, new_access_token, "null").save()

        response = Response()

        response.data = {
            'access_token': new_access_token
        }
        
        return response

class LogoutView(APIView):
    def post(self, request):
        token = request.headers
        access_token = "b'"+token['Authorization']+"'"
        if(token['Device'] == 'Desktop'):
            Desktop_token.objects.raw({'access_token':access_token}).first().delete()
        elif(token['Device'] == 'Mobile'):
            Mobile_token.objects.raw({'access_token':access_token}).first().delete()
        
        response = Response()
        response.data = {
            'message': 'Logged out successfully'
        }

        return response


class YoutubeView(APIView):
    def post(self, request):
        search_url = 'https://www.googleapis.com/youtube/v3/search'
        video_url = 'https://www.googleapis.com/youtube/v3/videos'
        search_params = {
            'part': 'snippet',
            'q': request.data['q'],
            'key': settings.YOUTUBE_DATA_API_KEY,
            'maxResults': 10,
            'type': 'video'
        }
        video_ids = []
        r = requests.get(search_url, params=search_params)
        results = r.json()['items']
        for result in results:
            video_ids.append(result['id']['videoId'])
        
        video_params = {
            'key': settings.YOUTUBE_DATA_API_KEY,
            'part': 'snippet,contentDetails',
            'id': ','.join(video_ids)
        }
        r = requests.get(video_url, params=video_params)
        results = r.json()['items']


        check_list = []
        for result in results:
            check_list.append(result['id'])
        search_query = {
                        "query": {
                            "terms": {
                            "id": check_list
                            }
                        }
                        }

        elasticsearch_url = settings.ELASTICSEARCH_URL
        elasticsearch_index = settings.ELASTICSEARCH_INDEXES['youtube_data_index']
        search_url = elasticsearch_url + elasticsearch_index + "_search"

        response = requests.get(search_url, json=search_query)

        existing_list = [{x['_source']['id']:x['_source']['title']} for x in response.json()['hits']['hits']]
        new_list = []
        data_to_be_inserted = []
        existing_videos = [i for s in [d.keys() for d in existing_list] for i in s]
        for result in results:
            if(result['id'] not in existing_videos):
                new_list.append({result['id']:result['snippet']['title']})
                data_to_be_inserted.append({
                    "id": result['id'],
                    "title": result['snippet']['title'],
                    "duration": result['contentDetails']['duration'],
                    "url": result['snippet']['thumbnails']['high']['url']
                })

        add.delay(data_to_be_inserted)
        return Response({
            "existing_list": existing_list,
            "new_list": new_list
        })