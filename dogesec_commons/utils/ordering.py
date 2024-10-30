from django.conf import settings
from rest_framework import pagination, response
from rest_framework.filters import OrderingFilter
from django.utils.encoding import force_str
from rest_framework import response

class Ordering(OrderingFilter):
    ordering_param = "sort"

    def get_ordering(self, request, queryset, view):
        params = request.query_params.get(self.ordering_param)
        ordering_mapping = self.get_ordering_mapping(queryset, view)
        if params:
            fields = [ordering_mapping.get(param.strip()) for param in params.split(',') if param.strip() in ordering_mapping]
            ordering = self.remove_invalid_fields(queryset, fields, view, request)
            if ordering:
                return ordering
        return self.get_default_ordering(view)

    def get_ordering_mapping(self, queryset, view):
        valid_fields = self.get_valid_fields(queryset, view)
        mapping = {}
        for k, v in valid_fields:
            mapping[f"{k}_descending"] = f"-{v}"
            mapping[f"{k}_ascending"]  = v
        return mapping
    

    def get_schema_operation_parameters(self, view):
        return [
            {
                'name': self.ordering_param,
                'required': False,
                'in': 'query',
                'description': force_str(self.ordering_description),
                'schema': {
                    'type': 'string',
                    'enum': list(self.get_ordering_mapping(None, view).keys())
                },
            },
        ]
    
    def get_default_ordering(self, view):
        ordering = getattr(view, 'ordering', None)
        if isinstance(ordering, str):
            return (self.get_ordering_mapping(None, view).get(ordering),)
        return None