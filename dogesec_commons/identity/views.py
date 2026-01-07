"""
Views for the Cyber Threat Exchange server.
"""

SEMANTIC_SEARCH_SORT_FIELDS = [
    "modified_descending",
    "modified_ascending",
    "created_ascending",
    "created_descending",
    "name_ascending",
    "name_descending",
    "type_ascending",
    "type_descending",
]

from django_filters.rest_framework import (
    CharFilter,
    DjangoFilterBackend,
    FilterSet,
    FilterSet,
    DjangoFilterBackend,
    CharFilter,
)
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter
from rest_framework import viewsets
from dogesec_commons.utils import Ordering, Pagination
from dogesec_commons.utils.schemas import DEFAULT_400_RESPONSE
from dogesec_commons.identity import serializers, models


@extend_schema_view(
    list=extend_schema(
        summary="List Identities",
        description="List all STIX Identity objects that can be used to create feeds.",
    ),
    retrieve=extend_schema(
        summary="Retrieve an Identity",
        description="Retrieve a STIX Identity object by its ID.",
    ),
    create=extend_schema(
        summary="Create an Identity",
        description="Create a new STIX Identity object.",
        responses={201: serializers.IdentitySerializer, 400: DEFAULT_400_RESPONSE},
    ),
    update=extend_schema(
        summary="Update an Identity",
        description="Update an existing STIX Identity object.",
        responses={200: serializers.IdentitySerializer, 400: DEFAULT_400_RESPONSE},
    ),
    destroy=extend_schema(
        summary="Delete an Identity",
        description="Delete a STIX Identity object.",
    ),
)
class IdentityView(viewsets.ModelViewSet):  # Changed from ReadOnlyModelViewSet
    http_method_names = ["get", "post", "put", "delete"]
    openapi_tags = ["Identities"]
    queryset = models.Identity.objects.all()
    serializer_class = serializers.IdentitySerializer
    pagination_class = Pagination("objects")
    lookup_field = "id"
    lookup_url_kwarg = "identity_id"
    lookup_value_regex = (
        r"identity--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    )
    filter_backends = [DjangoFilterBackend, Ordering]
    ordering_fields = ["created", "modified"]
    ordering = "modified_descending"
    openapi_path_params = [
        OpenApiParameter(
            "identity_id",
            type=OpenApiTypes.STR,
            location=OpenApiParameter.PATH,
            description="The ID of the Identity object (e.g. `identity--643fea2b-5da6-47a9-9433-f8e97669f75b`)",
        )
    ]

    class filterset_class(FilterSet):
        name = CharFilter(
            field_name="stix__name",
            lookup_expr="icontains",
            help_text="Filter by identity name (case-insensitive, partial match). e.g. `oge` would match `dogesec`, `DOGESEC`, etc.",
        )
