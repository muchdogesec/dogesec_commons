import txt2stix
from django.conf import settings
from django.db import models
from django.contrib.postgres.fields import ArrayField
import uuid
from functools import partial
import txt2stix.common
import txt2stix, txt2stix.extractions
from django.core.exceptions import ValidationError


class RelationshipMode(models.TextChoices):
    AI = "ai", "AI Relationship"
    STANDARD = "standard", "Standard Relationship"

def validate_extractor(types, name):
    extractors = txt2stix.extractions.parse_extraction_config(
            txt2stix.txt2stix.INCLUDES_PATH
        ).values()
    for extractor in extractors:
        if name == extractor.slug and extractor.type in types:
            return True
    raise ValidationError(f"{name} does not exist", 400)


class Profile(models.Model):
    id = models.UUIDField(primary_key=True)
    created = models.DateTimeField(auto_now_add=True)
    name = models.CharField(max_length=250, unique=True)
    extractions = ArrayField(base_field=models.CharField(max_length=256))
    relationship_mode = models.CharField(choices=RelationshipMode.choices, max_length=20, default=RelationshipMode.STANDARD)
    extract_text_from_image = models.BooleanField(default=False)
    defang = models.BooleanField(help_text='If the text should be defanged before processing')
    ai_settings_relationships = models.CharField(max_length=256, blank=False, null=True)
    ai_settings_extractions = ArrayField(base_field=models.CharField(max_length=256), default=list)
    ignore_image_refs = models.BooleanField(default=True)
    ignore_link_refs  = models.BooleanField(default=True)

    class Meta:
        app_label = settings.APP_LABEL


    def save(self, *args, **kwargs) -> None:
        if not self.id:
            self.id = uuid.uuid5(settings.STIX_NAMESPACE, self.name)
        return super().save(*args, **kwargs)