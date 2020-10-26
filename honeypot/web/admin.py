from django.contrib import admin
from .models import User, Attempt, UserPass, Passwords, Usernames, SqlInjection
# Register your models here.

class UserForm(admin.ModelAdmin):
    list_display = ['username', 'email']
    # get_readonly_fields = ['username', 'email', 'hashed_password', 'salt']

    def get_readonly_fields(self, request, obj=None):
        if obj:
            return self.readonly_fields + ('username', 'email', 'hashed_password', 'salt')
        return self.readonly_fields

class AttemptForm(admin.ModelAdmin):
    list_display = ['attempt_id','username', 'password', 'datetime', 'ip', 'country', 'user_agent', 'content_type', 'sql_injection']
    readonly_fields = [
        'attempt_id',
        'username', 
        'password', 
        'datetime', 
        'ip', 
        'user_agent', 
        'content_length', 
        'content_type', 'host', 
        'accept', 'accept_language', 
        'accept_encoding', 
        'server_name', 
        'server_port',
        'referer',
        'method',
        'query_string',
        'cookie',
        'payload',
        'country',
        'sql_injection']


class UserPassForm(admin.ModelAdmin):
    list_display = ['id', 'username', 'password', 'count']
    readonly_fields = ['id', 'username', 'password', 'count']


class UsernamesForm(admin.ModelAdmin):
    list_display = ['username', 'count']
    readonly_fields = ['username', 'count']


class PasswordsForm(admin.ModelAdmin):
    list_display = ['password', 'count']
    readonly_fields = ['password', 'count']


class SqliForm(admin.ModelAdmin):
    list_display = ['attempt', 'ip', 'payload']
    readonly_fields = ['attempt', 'ip', 'payload']



admin.site.register(User, UserForm)
admin.site.register(Attempt, AttemptForm)
admin.site.register(UserPass, UserPassForm)
admin.site.register(Usernames, UsernamesForm)
admin.site.register(Passwords, PasswordsForm)
admin.site.register(SqlInjection, SqliForm)