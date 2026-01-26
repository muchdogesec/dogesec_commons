import json
import stix2
import stix2.exceptions
from dogesec_commons.identity.models import Identity
from rest_framework import serializers, validators
from dogesec_commons.identity.models import Identity
from rest_framework import serializers, validators


class IdentitySerializer(serializers.ModelSerializer):
    instance: Identity
    id = serializers.CharField(
        validators=[validators.UniqueValidator(queryset=Identity.objects.all())]
    )

    class Meta:
        model = Identity
        fields = "__all__"
        extra_kwargs = {
            "stix": {"write_only": True, "required": False},
        }

    def to_representation(self, instance):
        return instance.dict

    def to_internal_value(self, data):
        ## do initial validation
        if not self.instance:
            super().to_internal_value(data)
        # actual validation
        data = dict(data.copy())

        if not isinstance(data, dict):
            raise serializers.ValidationError(
                {"non_field_errors": ["STIX Identity must be a JSON object (dict)."]}
            )
        if self.instance:
            if 'id' in data and data['id'] != self.instance.id:
                raise serializers.ValidationError(
                    {"id": ["Cannot modify 'id' of an existing Identity."]}
                )

        if self.instance:
            # For updates, merge existing stix data with new data
            data.update(self.instance.static_dict)
        try:
            identity = stix2.Identity(**data)
        except stix2.exceptions.STIXError as exc:
            raise serializers.ValidationError(
                {"stix_validation_error": [f"Invalid STIX Identity object: {exc}"]}
            )
        except Exception as exc:
            raise serializers.ValidationError(
                {"bad_data_error": [f"Unexpected STIX Validation error: {exc}"]}
            )
        value_dict = json.loads(identity.serialize())
        retval = {}
        retval["stix"] = value_dict.copy()
        retval["id"] = retval["stix"].pop("id")
        retval["modified"] = retval["stix"].pop("modified")
        retval["created"] = retval["stix"].pop("created")
        return retval

    def update(self, instance: Identity, validated_data):
        return super().update(instance, validated_data)

    def get_schema(self):
        UUID_RE = (
            "[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
        )
        return {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "$id": "https://example.com/stix/identity.schema.json",
            "title": "STIX 2.1 Identity Object",
            "type": "object",
            "required": [
                "type",
                "spec_version",
                "id",
                "created",
                "modified",
                "name",
                "identity_class",
            ],
            "properties": {
                "type": {"const": "identity"},
                "spec_version": {"const": "2.1"},
                "id": {
                    "type": "string",
                    "pattern": f"^identity--{UUID_RE}$",
                },
                "created": {"type": "string", "format": "date-time"},
                "modified": {"type": "string", "format": "date-time"},
                "created_by_ref": {
                    "type": "string",
                    "pattern": f"^identity--{UUID_RE}$",
                },
                "revoked": {"type": "boolean"},
                "labels": {"type": "array", "items": {"type": "string"}},
                "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
                "lang": {"type": "string"},
                "name": {"type": "string", "minLength": 1},
                "description": {"type": "string"},
                "identity_class": {
                    "type": "string",
                },
                "sectors": {"type": "array", "items": {"type": "string"}},
                "contact_information": {"type": "string"},
                "object_marking_refs": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "pattern": f"^marking-definition--{UUID_RE}$",
                    },
                },
                "external_references": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["source_name"],
                        "properties": {
                            "source_name": {"type": "string"},
                            "description": {"type": "string"},
                            "url": {"type": "string", "format": "uri"},
                            "external_id": {"type": "string"},
                        },
                        "additionalProperties": False,
                    },
                },
                "extensions": {
                    "type": "object",
                    "additionalProperties": {"type": "object"},
                },
            },
            "additionalProperties": True,
        }
