# Generated by Django 3.1.8 on 2021-04-07 11:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('archerysettings', '0003_auto_20200503_1201'),
    ]

    operations = [
        migrations.AddField(
            model_name='arachni_settings_db',
            name='arachni_pass',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='arachni_settings_db',
            name='arachni_user',
            field=models.TextField(blank=True, null=True),
        ),
    ]