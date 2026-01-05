import json
import uuid
from django.db import models
from django.utils import timezone
import stix2


class IdentityIDField(models.CharField):
    def pre_save(self, model_instance, add):
        if add and not getattr(model_instance, self.attname, None):
            value = "identity--" + str(uuid.uuid4())
            setattr(model_instance, self.attname, value)
            return value
        return super().pre_save(model_instance, add)


class AutoUpdatedModifiedField(models.DateTimeField):
    def pre_save(self, model_instance, add):
        value = getattr(model_instance, self.attname, None)
        if not add:
            value = timezone.now()
            setattr(model_instance, self.attname, value)
        return value


class Identity(models.Model):
    id = IdentityIDField(primary_key=True, max_length=64, default="")
    created = models.DateTimeField(default=None)
    modified = AutoUpdatedModifiedField(default=None)
    stix = models.JSONField(default=dict)

    def save(self, *args, **kwargs) -> None:
        if not self.created:
            self.created = timezone.now()
        if not self.modified:
            self.modified = self.created
        return super().save(*args, **kwargs)

    @property
    def static_dict(self):
        return {
            "type": "identity",
            "spec_version": "2.1",
            "id": self.id,
            "created": self.created,
            "modified": self.modified,
        }

    @property
    def identity(self):
        data = self.static_dict
        data.update(self.stix)
        return stix2.Identity(**data)

    @property
    def dict(self) -> dict:
        return json.loads(self.identity.serialize())
