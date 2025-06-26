import argparse
import contextlib
from functools import partial
import uuid
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
from dogesec_commons.utils.serializers import CommonErrorSerializer

from drf_spectacular.utils import OpenApiResponse, OpenApiExample

from drf_spectacular.utils import OpenApiResponse, OpenApiExample

from django.db import models


def validate_model(model):
    if not model:
        return None
    try:
        extractor = txt2stix.txt2stix.parse_model(model)
    except BaseException as e:
        raise ValidationError(f"invalid model: {model}")
    return model

def validate_extractor(typestr, types, name):
    extractors = txt2stix.extractions.parse_extraction_config(
            txt2stix.txt2stix.INCLUDES_PATH
        )
    if  name not in extractors or extractors[name].type not in types:
        raise ValidationError(f"`{name}` is not a valid {typestr}", 400)
    
def validate_stix_id(stix_id: str, type: str):
    type_part, _, id_part = stix_id.partition('--')
    if type_part != type:
        raise ValidationError(f"Invalid STIX ID for type `{type}`")
    with contextlib.suppress(Exception):
        uuid.UUID(id_part)
        return stix_id
    raise ValidationError("Invalid STIX ID")


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
    identity_id = serializers.CharField(
        max_length=46,
        validators=[lambda stix_id: validate_stix_id(stix_id, "identity")],
        allow_null=True,
        required=False,
        help_text="STIX Identity ID (e.g `identity--19686d47-3a50-48a0-8ef0-f3e0f8a4bd99`)"
    )

    ai_settings_relationships = serializers.CharField(
        validators=[validate_model],
        help_text='(required if AI relationship enabled): passed in format `provider:model`. Can only pass one model at this time.',
        allow_null=True,
        required=False,
    )
    ai_settings_extractions = serializers.ListField(
        child=serializers.CharField(max_length=256, validators=[validate_model]),
        help_text='(required if AI extractions enabled) passed in format provider[:model] e.g. openai:gpt4o. Can pass more than one value to get extractions from multiple providers. model part is optional',
        required=False,
    )
    ai_summary_provider = serializers.CharField(
        validators=[validate_model],
        help_text='you can optionally get an AI model to produce a summary of the blog. You must pass the request in format `provider:model`. model part is optional',
        allow_null=True,
        required=False,
    )
    ai_content_check_provider = serializers.CharField(
        max_length=256, validators=[validate_model],
        allow_null=True,
        required=False,
        help_text='check content before proceeding'
    )
    ai_create_attack_flow = serializers.BooleanField(required=False, help_text="should create attack-flow (default is `false`)", default=True)
    extractions = serializers.ListField(
        min_length=1,
        child=serializers.CharField(max_length=256, validators=[partial(validate_extractor, 'extractor', ["ai", "pattern", "lookup"])]),
        help_text="extraction id(s)",
    )
    defang = serializers.BooleanField(help_text='If the text should be defanged before processing')


    ignore_embedded_relationships     = serializers.BooleanField(required=False, help_text="applies to SDO and SCO types (default is `false`)")
    ignore_embedded_relationships_sro = serializers.BooleanField(required=False, help_text="sets wether to ignore embedded refs on `relationship` object types (default is `true`)")
    ignore_embedded_relationships_smo = serializers.BooleanField(required=False, help_text="sets wether to ignore embedded refs on SMO object types (`marking-definition`, `extension-definition`, `language-content`) (default is `true`)")
    generate_pdf = serializers.BooleanField(required=False, help_text="Whether or not to generate pdf file for input, applies to both stixify and obstracts (default is `false`)")

    class Meta:
        model = Profile
        fields = "__all__"

    def validate(self, attrs):
        if not attrs.get('ai_settings_relationships'):
            if attrs['relationship_mode'] == 'ai':
                raise ValidationError('`ai_settings_relationships` is required when `relationship_mode == "ai"`')
            if attrs['ai_create_attack_flow']:
                raise ValidationError('`ai_settings_relationships` is required when `ai_create_attack_flow == true`')
        if not attrs.get('ai_settings_extractions'):
            uses_ai(attrs['extractions'])
        return super().validate(attrs)



DEFAULT_400_ERROR = OpenApiResponse(
    CommonErrorSerializer,
    "The server did not understand the request",
    [
        OpenApiExample(
            "http400",
            {"message": " The server did not understand the request", "code": 400},
        )
    ],
)


DEFAULT_404_ERROR = OpenApiResponse(
    CommonErrorSerializer,
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
    description = serializers.CharField(required=False, allow_null=True)
    notes = serializers.CharField(required=False, allow_null=True)
    file = serializers.CharField(required=False, allow_null=True)
    created = serializers.CharField(required=False, allow_null=True)
    modified = serializers.CharField(required=False, allow_null=True)
    created_by = serializers.CharField(required=False, allow_null=True)
    version = serializers.CharField()
    stix_mapping = serializers.CharField(required=False, allow_null=True)
    dogesec_web = serializers.BooleanField(required=False, allow_null=True)

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
        KEYS = cls(data={}).get_fields()
        retval = {"id": dct["slug"]}
        for key in KEYS:
            if key in dct:
                retval[key] = dct[key]
        return retval

