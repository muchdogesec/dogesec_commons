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

import textwrap

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
        description=textwrap.dedent(
            """
            Upload a valid STIX Identity object.

            The Identity object will be validated against the STIX specification.

            Some notes about Identity creation to be aware of

            * The Identity object you submit will be unmodified in this request
            * All properties will be validated against the STIX specification to ensure compliance. If validation fails, the object will not be updated.
            * You can use custom properties. These will not be validated against any schema.
            """
        ),
        responses={201: serializers.IdentitySerializer, 400: DEFAULT_400_RESPONSE},
    ),
    update=extend_schema(
        summary="Update an Identity",
        description=textwrap.dedent(
            """
            Update a STIX Identity object.

            When an Identity object is updated, all references to this identity will point to the latest version you upload.

            IMPORTANT behaviour to be aware of:

            * You cannot edit the following properties in this request: `spec_version`, `modified`, `created`, `type`. You should pass the full identity object, but they will be ignored in processing.
            * The `id` passed in the body must match the `id` passed in URL of the request.
            * On update, the `modified` time of the object will be updated to match the current time. The `created` date will remain the same
            * All changes will be validated against the STIX specification to ensure compliance. If validation fails, the object will not be updated.
            * You cannot modify an Identity uploaded to a Feed using this endpoint. You must update it using the Feed objects endpoints.
            """
        ),
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
