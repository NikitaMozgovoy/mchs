# Generated by Django 3.1.7 on 2022-01-10 20:45

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0042_auto_20220110_1818'),
    ]

    operations = [
        migrations.AddField(
            model_name='post',
            name='fullname',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='person', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='post',
            name='value',
            field=models.CharField(max_length=30, unique=True, verbose_name='Должность'),
        ),
    ]