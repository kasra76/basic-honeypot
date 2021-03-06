# Generated by Django 3.0.8 on 2020-07-11 14:38

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('web', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Attempt',
            fields=[
                ('attempt_id', models.AutoField(primary_key=True, serialize=False)),
                ('username', models.CharField(max_length=255)),
                ('password', models.CharField(max_length=255)),
                ('datetime', models.DateTimeField()),
                ('ip', models.GenericIPAddressField()),
                ('user_agent', models.CharField(max_length=511)),
                ('content_length', models.IntegerField()),
                ('content_type', models.CharField(max_length=255)),
                ('host', models.GenericIPAddressField()),
                ('accept', models.CharField(max_length=255)),
                ('accept_language', models.CharField(max_length=255)),
                ('accept_encoding', models.TextField()),
                ('origin', models.GenericIPAddressField()),
                ('connection', models.CharField(max_length=255)),
                ('referer', models.GenericIPAddressField()),
                ('cookie', models.CharField(max_length=1023)),
                ('sessionid', models.CharField(max_length=1023)),
                ('upgrade_insecure_request', models.IntegerField()),
            ],
        ),
    ]
