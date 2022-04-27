from django.urls import path
from .views import RegisterView, LoginView, UserView, RefreshTokenView, LogoutView
from rest_framework.authtoken import views


urlpatterns = [
    path('register', RegisterView.as_view()),
    path('login', LoginView.as_view()),
    path('user', UserView.as_view()),
    path('logout', LogoutView.as_view()),
    path('refresh-token', RefreshTokenView.as_view()),
]