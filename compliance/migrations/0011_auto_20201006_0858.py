# Generated by Django 3.1.2 on 2020-10-06 08:58

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("compliance", "0010_auto_20201004_1522"),
    ]

    operations = [
        migrations.RenameField(
            model_name="inspec_scan_db",
            old_name="SEVERITY_HIGH",
            new_name="high_vul",
        ),
        migrations.RenameField(
            model_name="inspec_scan_db",
            old_name="SEVERITY_MEDIUM",
            new_name="medium_vul",
        ),
    ]