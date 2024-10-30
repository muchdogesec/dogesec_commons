from rest_framework import serializers

from . import conf
from .models import Profile
from rest_framework import serializers
import txt2stix.extractions
import txt2stix.txt2stix
from urllib.parse import urljoin
from django.conf import settings


from drf_spectacular.utils import OpenApiResponse, OpenApiExample

from drf_spectacular.utils import OpenApiResponse, OpenApiExample

class ErrorSerializer(serializers.Serializer):
    message = serializers.CharField(required=True)
    code    = serializers.IntegerField(required=True)
    details = serializers.DictField(required=False)

class ProfileSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)

    class Meta:
        model = Profile
        fields = "__all__"



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

