# Generated by Django 5.0.4 on 2024-05-01 13:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('AppFinal', '0007_alter_student_speciality'),
    ]

    operations = [
        migrations.AddField(
            model_name='student',
            name='img_url',
            field=models.URLField(blank=True, max_length=90, null=True),
        ),
        migrations.AddField(
            model_name='student',
            name='score',
            field=models.IntegerField(default=0),
        ),
    ]