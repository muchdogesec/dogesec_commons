# Generated by Django 5.1.5 on 2025-02-18 11:00

import django.contrib.postgres.fields
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Profile',
            fields=[
                ('id', models.UUIDField(primary_key=True, serialize=False)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('name', models.CharField(max_length=250, unique=True)),
                ('extractions', django.contrib.postgres.fields.ArrayField(base_field=models.CharField(max_length=256), size=None)),
                ('relationship_mode', models.CharField(choices=[('ai', 'AI Relationship'), ('standard', 'Standard Relationship')], default='standard', max_length=20)),
                ('extract_text_from_image', models.BooleanField(default=False)),
                ('defang', models.BooleanField()),
                ('ai_settings_relationships', models.CharField(max_length=256, null=True)),
                ('ai_settings_extractions', django.contrib.postgres.fields.ArrayField(base_field=models.CharField(max_length=256), default=list, size=None)),
                ('ai_summary_provider', models.CharField(max_length=256, null=True)),
                ('ignore_image_refs', models.BooleanField(default=True)),
                ('ignore_link_refs', models.BooleanField(default=True)),
                ('ignore_extraction_boundary', models.BooleanField(default=False)),
                ('ignore_embedded_relationships_sro', models.BooleanField(default=True)),
                ('ignore_embedded_relationships_smo', models.BooleanField(default=True)),
                ('ignore_embedded_relationships', models.BooleanField(default=False)),
            ],
        ),
    ]
