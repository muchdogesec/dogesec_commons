import argparse
from rest_framework import serializers

from . import conf
from .models import Profile
from rest_framework import serializers
import txt2stix.extractions
import txt2stix.txt2stix
from urllib.parse import urljoin
from django.conf import settings
from django.contrib.postgres.fields import ArrayField
from rest_framework.validators import ValidationError


from drf_spectacular.utils import OpenApiResponse, OpenApiExample

from drf_spectacular.utils import OpenApiResponse, OpenApiExample

from django.db import models

class ErrorSerializer(serializers.Serializer):
    message = serializers.CharField(required=True)
    code    = serializers.IntegerField(required=True)
    details = serializers.DictField(required=False)

def validate_model(model):
    if not model:
        return None
    try:
        extractor = txt2stix.txt2stix.parse_model(model)
    except BaseException as e:
        raise ValidationError(str(e))
    return model

def uses_ai(slugs):
    extractors = txt2stix.extractions.parse_extraction_config(
            txt2stix.txt2stix.INCLUDES_PATH
        )
    ai_based_extractors = []
    for slug in slugs:
        if extractors[slug].type == 'ai':
            ai_based_extractors.append(slug)
    
    if ai_based_extractors:
        raise ValidationError(f'AI based extractors `{ai_based_extractors}` used when `ai_settings_extractions` is not configured')

class ProfileSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)
    ai_settings_relationships = serializers.CharField(
        validators=[validate_model],
        help_text='(required if AI relationship enabled): passed in format `provider:model`. Can only pass one model at this time.',
        allow_null=True,
        required=False,
    )
    ai_settings_extractions = serializers.ListField(
        child=serializers.CharField(max_length=256, validators=[validate_model]),
        help_text='(required if AI extractions enabled) passed in format provider[:model] e.g. openai:gpt4o. Can pass more than one value to get extractions from multiple providers. model part is optional',
    )

    class Meta:
        model = Profile
        fields = "__all__"

    def validate(self, attrs):
        if attrs['relationship_mode'] == 'ai' and not attrs['ai_settings_relationships']:
            raise ValidationError('AI `relationship_mode` requires a valid `ai_settings_relationships`')
        if not attrs['ai_settings_extractions']:
            uses_ai(attrs['extractions'])
        return super().validate(attrs)



DEFAULT_400_ERROR = OpenApiResponse(
    ErrorSerializer,
    "The server did not understand the request",
    [
        OpenApiExample(
            "http400",
            {"message": " The server did not understand the request", "code": 400},
        )
    ],
)


DEFAULT_404_ERROR = OpenApiResponse(
    ErrorSerializer,
    "Resource not found",
    [
        OpenApiExample(
            "http404",
            {
                "message": "The server cannot find the resource you requested",
                "code": 404,
            },
        )
    ],
)


##



class Txt2stixExtractorSerializer(serializers.Serializer):
    id = serializers.CharField(label='The `id` of the extractor')
    name = serializers.CharField()
    type = serializers.CharField()
    description = serializers.CharField()
    notes = serializers.CharField()
    file = serializers.CharField()
    created = serializers.CharField()
    modified = serializers.CharField()
    created_by = serializers.CharField()
    version = serializers.CharField()
    stix_mapping = serializers.CharField()

    @classmethod
    def all_extractors(cls, types):
        retval = {}
        extractors = txt2stix.extractions.parse_extraction_config(
            txt2stix.txt2stix.INCLUDES_PATH
        ).values()
        for extractor in extractors:
            if extractor.type in types:
                retval[extractor.slug] = cls.cleanup_extractor(extractor)
                if extractor.file:
                    retval[extractor.slug]["file"] = urljoin(conf.TXT2STIX_INCLUDE_URL, str(extractor.file.relative_to(txt2stix.txt2stix.INCLUDES_PATH)))
        return retval
    
    @classmethod
    def cleanup_extractor(cls, dct: dict):
        KEYS = ["name", "type", "description", "notes", "file", "created", "modified", "created_by", "version", "stix_mapping"]
        retval = {"id": dct["slug"]}
        for key in KEYS:
            if key in dct:
                retval[key] = dct[key]
        return retval

