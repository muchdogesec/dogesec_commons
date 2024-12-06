from typing import List
from drf_spectacular.openapi import AutoSchema
from drf_spectacular.plumbing import ComponentRegistry
from drf_spectacular.utils import _SchemaType, OpenApiResponse, OpenApiExample
from drf_spectacular.types import OpenApiTypes
import uritemplate

from dogesec_commons.utils import schemas
from .serializers import CommonErrorSerializer

from drf_spectacular.contrib.django_filters import DjangoFilterExtension, get_view_model
class OverrideDjangoFilterExtension(DjangoFilterExtension):
    priority = 10
    def get_schema_operation_parameters(self, auto_schema: AutoSchema, *args, **kwargs):
        model = get_view_model(auto_schema.view)
        if not model:
            return self.override(auto_schema, *args, **kwargs)
        return super().get_schema_operation_parameters(auto_schema, *args, **kwargs)
    
    def override(self, autoschema, *args, **kwargs):
        result = []
        filterset_class = self.target.get_filterset_class(autoschema.view)
        if not filterset_class:
            return self.target.get_schema_operation_parameters(autoschema.view, *args, **kwargs)
        for field_name, filter_field in filterset_class.base_filters.items():
            result += self.resolve_filter_field(
                autoschema, None, filterset_class, field_name, filter_field
            )
        return result


class CustomAutoSchema(AutoSchema):
    default_responses = {
            '404': (schemas.WEBSERVER_404_RESPONSE, ["application/json"]),
    }
    def get_tags(self) -> List[str]:
        if hasattr(self.view, "openapi_tags"):
            return self.view.openapi_tags
        return super().get_tags()

    
    def get_override_parameters(self):
        params = super().get_override_parameters()
        path_variables = uritemplate.variables(self.path)
        for param in getattr(self.view, 'openapi_path_params', []):
            if param.name in path_variables:
                params.append(param)
        return params
    
    def _map_serializer_field(self, field, direction, bypass_extensions=False):
        if getattr(field, 'internal_serializer', None):
            return super()._map_serializer_field(field.internal_serializer, direction, bypass_extensions)
        return super()._map_serializer_field(field, direction, bypass_extensions)


    def _map_serializer(self, serializer, direction, bypass_extensions=False):
        if getattr(serializer, "get_schema", None):
            return serializer.get_schema()
        return super()._map_serializer(serializer, direction, bypass_extensions)
    

    def get_operation(self, *args, **kwargs):
        operation = super().get_operation(*args, **kwargs)
        if operation:
            self.add_default_pages(operation)
        return operation

    def add_default_pages(self, operation):
        """
        modify responses to include 404 error for when path parameters don't match specified path. e.g if integer passed instead of a uuid param
        """
        responses = operation['responses']

        default_responses = {
            code: self._get_response_for_code(schema, code, content_type) for code, (schema, content_type) in self.default_responses.items()
        }
        for code, content_response in default_responses.items():
            if code not in responses:
                responses[code] = content_response
        return operation
    
    def _is_list_view(self, serializer=None) -> bool:
        if getattr(self.view, 'action', None) == 'list' and getattr(self.view, 'skip_list_view', False):
            """
            view.skip_list_view is used for checking if many should be used or not on list() action
            """
            return False
        return super()._is_list_view(serializer)