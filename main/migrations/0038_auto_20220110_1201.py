# Generated by Django 3.1.7 on 2022-01-10 12:01

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0037_auto_20220110_1201'),
    ]

    operations = [
        migrations.AlterField(
            model_name='initialtrainingperiod',
            name='fullname',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='main.customuser'),
        ),
    ]