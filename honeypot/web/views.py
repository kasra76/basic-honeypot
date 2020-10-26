from datetime import datetime
from json import JSONEncoder, dump, dumps
from random import randrange

import requests
from django.core import serializers
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, render
from django.views.decorators.csrf import csrf_exempt

from web.models import (Attempt, Passwords, SqlInjection, User, Usernames,
                        UserPass)

from .utilities import (hashPassword, is_password_malicious,
                        is_username_malicious)

# from django.contrib.gis.geoip2 import GeoIP2


# Create your views here.
@csrf_exempt
def register_user(request):
    """register a user in system"""

    if 'username' in request.POST.keys():
        this_username = request.POST['username']
    if 'email' in request.POST.keys():
        email = request.POST['email']
    if 'password' in request.POST.keys():
        password = request.POST['password']
        salt = str(randrange(10 ** 48, 10 ** 49))
        hashed_password = hashPassword(password, salt)
    
    if User.objects.filter(username=this_username).count() != 0:
        return JsonResponse({
            'status': 'Error',
            'message': 'username was already defined'
        }, encoder=JSONEncoder)

    if User.objects.filter(email=email).count() != 0:
        return JsonResponse({
            'status': 'Error',
            'message': 'Email is used before'
        }, encoder=JSONEncoder)
    
    # User.objects.create(username=this_username, email=email, phone_number=phone_number, 
    #     salt=salt, hashed_password=hashed_password)
    new_user = User(username=this_username, email=email, salt=salt, 
            hashed_password=hashed_password)
    new_user.save()
    return JsonResponse({
        'status' : 'ok',
        'message' : 'User registerd'
    }, encoder=JSONEncoder)


@csrf_exempt
def login(request):
    """login user"""
    
    payload = request.POST

    if 'username' not in request.POST.keys():
        return JsonResponse({
            'status': 'Error',
            'message': 'username field is empty'
        }, encoder=JSONEncoder)
    if 'password' not in request.POST.keys():
        return JsonResponse({
            'status': 'Error',
            'message': 'password field is empty'
        }, encoder=JSONEncoder)


    this_username = payload['username']
    this_password = payload['password']
    date_time = datetime.now()
    if 'REMOTE_ADDR' in request.META.keys():
        ip = request.META['REMOTE_ADDR']
    else:
        ip = None
    if 'HTTP_USER_AGENT' in request.META.keys():    
        user_agent = request.META['HTTP_USER_AGENT']
    else:
        user_agent = None
    if 'CONTENT_LENGTH' in request.META.keys():    
        content_length = request.META['CONTENT_LENGTH']
    content_type = request.content_type
    if 'HTTP_HOST' in request.META.keys():    
        host = request.META['HTTP_HOST']
    else:
        host = None
    if 'HTTP_ACCEPT' in request.META.keys():    
        accept = request.META['HTTP_ACCEPT']
    else:
        accept = None
    if 'HTTP_ACCEPT_LANGUAGE' in request.META.keys():        
        accept_language = request.META['HTTP_ACCEPT_LANGUAGE']
    else:
        accept_language = None
    if 'HTTP_ACCEPT_ENCODING' in request.META.keys():
        accept_encoding = request.META['HTTP_ACCEPT_ENCODING']
    else:
        accept_encoding = None
    if 'SERVER_NAME' in request.META.keys():
        server_name = request.META['SERVER_NAME']
    else:
        server_name = None
    if 'SERVER_PORT' in request.META.keys():
        server_port = request.META['SERVER_PORT']
    else:
        server_port = None
    if 'HTTP_REFERER' in request.META.keys():
        referer = request.META['HTTP_REFERER']
    else:
        referer = None
    if "REQUEST_METHOD" in request.META.keys():
        method = request.META["REQUEST_METHOD"]
    else:
        method = 'POST'
    if 'QUERY_STRING' in request.META.keys():
        query_string = request.META['QUERY_STRING']
    else:
        query_string = None
    if 'HTTP_COOKIE' in request.META.keys():
        cookie = request.META['HTTP_COOKIE']
    else:
        cookie = None
    r = requests.get(url=f"https://ip2c.org/{ip}")
    country = r.content.decode('ascii').split(';')
    country = country[len(country) - 1]

    # === Add to Usernames and Passwords table ===
    
    if Passwords.objects.filter(password=this_password).count() == 0:
        pass_obj = Passwords(password=this_password)
        pass_obj.save()
    else:
        pass_obj = Passwords.objects.get(password=this_password)
        pass_obj.count += 1
        pass_obj.save()

    if Usernames.objects.filter(username=this_username).count() == 0:
        username_obj = Usernames(username=this_username)
        username_obj.save()
    else:
        username_obj = Usernames.objects.get(username=this_username)
        username_obj.count += 1
        username_obj.save()


    attempt = Attempt(
        username=this_username, 
        password=this_password, 
        datetime=date_time,
        ip=ip,
        user_agent=user_agent,
        content_length=content_length,
        content_type=content_type,
        host=host,
        accept=accept,
        accept_language=accept_language,
        accept_encoding=accept_encoding,
        server_name=server_name,
        server_port=server_port,
        referer=referer,
        method=method,
        query_string=query_string,
        cookie=cookie,
        payload=payload,
        country=country
        )
    attempt.save()



    if UserPass.objects.filter(username=this_username, password=this_password).count() == 0:
        userPass_obj = UserPass(username=this_username, password=this_password)
        userPass_obj.save()
    else:
        userPass_obj = UserPass.objects.get(username=this_username, password=this_password)
        userPass_obj.count += 1
        userPass_obj.save()

    # SQL Injection
    if is_username_malicious(this_username) or is_password_malicious(this_password):
        attempt.sql_injection = True
        sqli_obj = SqlInjection(attempt=attempt, ip=ip, payload=payload)
        sqli_obj.save()
        attempt.save()
    

    if User.objects.filter(username=this_username).count() == 0:
        context = {
            'status': 'Error', 
            'message': f'No user with username \"{this_username}\"'
        }
        return render(request, 'index.html', context)

    user_obj = User.objects.get(username=this_username)
    if hashPassword(this_password, user_obj.salt) == user_obj.hashed_password:
        return JsonResponse({
            'status': 'ok',
            'message': 'user loged in'
        }, encoder=JSONEncoder)
    else:
        context = {
            'status': 'Error',
            'message': 'wrong password'
        }
        return render(request, 'index.html', context=context)
            


def home_page(request):
    if request.method == 'GET':
        return render(request, 'index.html')
