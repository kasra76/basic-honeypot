# Generated by Django 3.0.8 on 2020-07-17 10:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('web', '0009_auto_20200717_0730'),
    ]

    operations = [
        migrations.AlterField(
            model_name='attempt',
            name='payload',
            field=models.CharField(default=None, max_length=255),
        ),
        migrations.AlterField(
            model_name='attempt',
            name='query_string',
            field=models.CharField(max_length=255, null=True),
        ),
    ]
