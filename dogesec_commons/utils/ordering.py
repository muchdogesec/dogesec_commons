from django.conf import settings
from rest_framework import pagination, response
from rest_framework.filters import OrderingFilter
from django.utils.encoding import force_str
from rest_framework import response


class Ordering(OrderingFilter):
    ordering_param = "sort"

    def get_ordering(self, request, queryset, view):
        sort_params = set()
        if request:
            if request.query_params.get(self.ordering_param):
                sort_params = set(request.query_params.get(self.ordering_param).split(","))
        ordering_mapping = self.get_ordering_mapping(queryset, view)
        sort_params = list(sort_params.intersection(ordering_mapping.keys()))
        if sort_params:
            ordering = []
            for param in sort_params:
                o = ordering_mapping[param]
                if isinstance(o, str):
                    o = [o]
                ordering.extend(o)
            return ordering
        return self.get_default_ordering(view)

    def get_ordering_mapping(self, queryset, view):
        valid_fields = getattr(view, "ordering_fields", self.ordering_fields)
        if isinstance(valid_fields, dict):
            return valid_fields

        valid_fields = self.get_valid_fields(queryset, view)
        mapping = {}
        for k, v in valid_fields:
            mapping[f"{k}_descending"] = [f"-{v}"]
            mapping[f"{k}_ascending"] = [v]
        return mapping

    def get_schema_operation_parameters(self, view):
        return [
            {
                "name": self.ordering_param,
                "required": False,
                "in": "query",
                "description": force_str(self.ordering_description),
                "schema": {
                    "type": "string",
                    "enum": list(self.get_ordering_mapping(None, view).keys()),
                },
            },
        ]

    def get_default_ordering(self, view):
        ordering = getattr(view, "ordering", None)
        if isinstance(ordering, str):
            return self.get_ordering_mapping(None, view).get(ordering)
        return None
