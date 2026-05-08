from django.db import models


class ModelForTesting(models.Model):
    name = models.CharField(max_length=100)
    created = models.DateTimeField()

    class Meta:
        ordering = ['-created', 'id']