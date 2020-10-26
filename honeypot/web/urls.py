from django.urls import path
from . import views

urlpatterns = [
    path('register/user/', views.register_user, name='Register User'),
    path('login/', views.login, name='Login User'),
    path('', views.home_page, name='Home Page')
]