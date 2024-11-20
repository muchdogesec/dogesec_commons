import logging
from rest_framework import serializers

from django.core.exceptions import ObjectDoesNotExist
from django.utils.translation import gettext_lazy as _

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema_field



class RelatedObjectField(serializers.RelatedField):
    lookup_key = 'pk'
    default_error_messages = {
        'required': _('This field is required.'),
        'does_not_exist': _('Invalid {lookup_key} "{lookup_value}" - object does not exist.'),
        'incorrect_type': _('Incorrect type. Expected valid {lookup_key} value, received "{lookup_value}", type: {data_type}.'),
    }
    def __init__(self, /, serializer, use_raw_value=False, **kwargs):
        self.internal_serializer: serializers.Serializer = serializer
        self.use_raw_value = use_raw_value
        super().__init__(**kwargs)

    def to_internal_value(self, data):
        try:
            instance = self.get_queryset().get(**{self.lookup_key: data})
            if self.use_raw_value:
                return data
            return instance
        except ObjectDoesNotExist as e:
            self.fail('does_not_exist', lookup_value=data, lookup_key=self.lookup_key)
        except BaseException as e:
            logging.exception(e)
            self.fail('incorrect_type', data_type=type(data), lookup_value=data, lookup_key=self.lookup_key)
        
    def to_representation(self, value):
        return self.internal_serializer.to_representation(value)


@extend_schema_field(OpenApiTypes.ANY)
class AnyField(serializers.Field):
    pass

class CommonErrorSerializer(serializers.Serializer):
    message = serializers.CharField(required=False)
    code    = serializers.IntegerField(required=True)
    details = serializers.JSONField(required=False)