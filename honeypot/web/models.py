from django.db import models
from datetime import datetime
from django.utils.timezone import now

# Create your models here.

class User(models.Model):
    username = models.CharField(max_length=255)
    email = models.EmailField()
    salt = models.CharField(max_length=128)
    hashed_password = models.CharField(max_length=400)

    def __str__(self):
        return f"{self.username}"


class Attempt(models.Model):
    attempt_id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=255, default="")
    password = models.CharField(max_length=255, default="")
    datetime = models.DateTimeField(default=now)
    ip = models.GenericIPAddressField(null=False, editable=False, default="")
    user_agent = models.CharField(max_length=511, default="")
    content_length = models.IntegerField(default=0)
    content_type = models.CharField(max_length=255, null=True)
    host = models.URLField(null=True)
    accept = models.CharField(max_length=255, null=True)
    accept_language = models.CharField(max_length=255, null=True)
    accept_encoding = models.CharField(max_length=255, null=True)
    server_name = models.CharField(max_length=255, default="")
    server_port = models.IntegerField(default=0)
    referer = models.URLField(null=True)
    method = models.CharField(max_length=15, default='POST')
    query_string = models.CharField(max_length=255, null=True)
    cookie = models.CharField(max_length=1023, null=True)
    payload = models.CharField(max_length=255, default=None)
    country = models.CharField(max_length=255, null=True)
    sql_injection = models.BooleanField(default=False)

    def __str__(self):
        return f'attemp id : {self.attempt_id}'

#TODO
class SqlInjection(models.Model):
    attempt = models.OneToOneField(Attempt, on_delete=models.CASCADE, primary_key=True, default=None)
    ip = models.GenericIPAddressField(null=True)
    payload = models.CharField(max_length=255, null=True)


class UserPass(models.Model):
    id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    count = models.IntegerField(default=1)

class Passwords(models.Model):
    password = models.CharField(max_length=255)
    count = models.IntegerField(default=1)


class Usernames(models.Model):
    username = models.CharField(max_length=255)
    count = models.IntegerField(default=1)