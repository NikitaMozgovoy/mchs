# Generated by Django 3.1.7 on 2022-01-02 20:50

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0026_remove_passedapprovals_why'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='customuser',
            name='why',
        ),
        migrations.AddField(
            model_name='passedapprovals',
            name='why',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='main.noattestation', verbose_name='Почему не прошел аттестацию'),
        ),
        migrations.AlterField(
            model_name='passedapprovals',
            name='id',
            field=models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID'),
        ),
    ]