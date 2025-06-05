from rest_framework.filters import BaseFilterBackend
from datetime import datetime, UTC
from django.forms import DateTimeField
from django_filters.rest_framework import filters


class DatetimeFieldUTC(DateTimeField):
    def to_python(self, value):
        value = super().to_python(value)
        return value and value.astimezone(UTC)


class DatetimeFilter(filters.Filter):
    field_class = DatetimeFieldUTC


class MinMaxDateFilter(BaseFilterBackend):
    min_val = datetime.min
    max_value = datetime.max

    def get_fields(self, view):
        out = {}
        fields = getattr(view, "minmax_date_fields", [])
        if not isinstance(fields, list):
            return out
        for field in fields:
            out[f"{field}_max"] = field
            out[f"{field}_min"] = field
        return out

    def parse_date(self, value):
        return DatetimeFieldUTC().to_python(value)

    def filter_queryset(self, request, queryset, view):
        valid_fields = self.get_fields(view)
        valid_params = [
            (k, v) for k, v in request.query_params.items() if k in valid_fields
        ]
        queries = {}
        for param, value in valid_params:
            field_name = valid_fields[param]
            if param.endswith("_max"):
                queries[f"{field_name}__lte"] = self.parse_date(value)
            else:
                queries[f"{field_name}__gte"] = self.parse_date(value)
        return queryset.filter(**queries)

    def get_schema_operation_parameters(self, view):
        parameters = []
        valid_fields = self.get_fields(view)
        for query_name, field_name in valid_fields.items():
            _type = "Maximum"
            if query_name.endswith("min"):
                _type = "Minimum"
            parameter = {
                "name": query_name,
                "required": False,
                "in": "query",
                "description": f"{_type} value of `{field_name}` to filter by in format `YYYY-MM-DD`.",
                "schema": {
                    "type": "string",
                    "format": "date",
                },
            }
            parameters.append(parameter)
        return parameters
