from django.conf import settings
from rest_framework import pagination, response
from rest_framework.filters import OrderingFilter
from django.utils.encoding import force_str
from rest_framework import response


class Pagination(pagination.PageNumberPagination):
    max_page_size = settings.MAXIMUM_PAGE_SIZE
    page_size = settings.DEFAULT_PAGE_SIZE
    page_size_query_param = 'page_size'
    def __init__(self, results_key) -> None:
        self.results_key = results_key
        super().__init__()

    def get_paginated_response(self, data):
        
        return response.Response({
            'page_size': self.get_page_size(self.request),
            'page_number': self.page.number,
            'page_results_count': len(self.page),
            'total_results_count': self.page.paginator.count,
            self.results_key: data,
        })

    def get_paginated_response_schema(self, schema):
        return {
            'type': 'object',
            'required': ['count', self.results_key],
            'properties': {
                'page_size': {
                    'type': 'integer',
                    'example': self.max_page_size,
                },
                'page_number': {
                    'type': 'integer',
                    'example': 3,
                },
                'page_results_count': {
                    'type': 'integer',
                    'example': self.max_page_size,
                },
                'total_results_count': {
                    'type': 'integer',
                    'example': 3,
                },
                self.results_key: schema,
            },
        }

    def __call__(self, *args, **kwargs):
        return self.__class__(results_key=self.results_key)
    

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

