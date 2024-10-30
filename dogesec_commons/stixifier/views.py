from .models import Profile
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter
from drf_spectacular.types import OpenApiTypes
from .utils import Pagination, Ordering

from rest_framework import viewsets, response, mixins
from django_filters.rest_framework import DjangoFilterBackend, FilterSet, Filter
from .serializers import DEFAULT_400_ERROR, DEFAULT_404_ERROR, Txt2stixExtractorSerializer

from .serializers import ProfileSerializer

from drf_spectacular.utils import extend_schema, extend_schema_view

import textwrap



@extend_schema_view(
    list=extend_schema(
        summary="Search profiles",
        description="Profiles determine how txt2stix processes the text in each File. A profile consists of an extractors, aliases, and/or whitelists. You can search for existing profiles here.",
        responses={400: DEFAULT_400_ERROR, 200: ProfileSerializer},
    ),
    retrieve=extend_schema(
        summary="Get a profile",
        description="View the configuration of an existing profile. Note, existing profiles cannot be modified.",
        responses={400: DEFAULT_400_ERROR, 404: DEFAULT_404_ERROR, 200: ProfileSerializer}
    ),
    create=extend_schema(
        summary="Create a new profile",
                description=textwrap.dedent(
            """
            Add a new Profile that can be applied to new Files. A profile consists of extractors, aliases, and/or whitelists. You can find available extractors, aliases, and whitelists via their respective endpoints.\n\n
            The following key/values are accepted in the body of the request:\n\n
            * `name` (required - must be unique)
            * `extractions` (required - at least one extraction ID): can be obtained from the GET Extractors endpoint. This is a [txt2stix](https://github.com/muchdogesec/txt2stix/) setting.
            * `whitelists` (optional): can be obtained from the GET Whitelists endpoint. This is a [txt2stix](https://github.com/muchdogesec/txt2stix/) setting.
            * `aliases` (optional): can be obtained from the GET Whitelists endpoint. This is a [txt2stix](https://github.com/muchdogesec/txt2stix/) setting.
            * `relationship_mode` (required): either `ai` or `standard`. Required AI provider to be configured if using `ai` mode. This is a [txt2stix](https://github.com/muchdogesec/txt2stix/) setting.
            * `extract_text_from_image` (required - boolean): wether to convert the images found in a blog to text. Requires a Google Vision key to be set. This is a [file2txt](https://github.com/muchdogesec/file2txt) setting.
            * `defang` (required - boolean): wether to defang the observables in the blog. e.g. turns `1.1.1[.]1` to `1.1.1.1` for extraction. This is a [file2txt](https://github.com/muchdogesec/file2txt) setting.\n\n
            A profile `id` is generated using a UUIDv5. The namespace used is `e92c648d-03eb-59a5-a318-9a36e6f8057c`, and the `name` is used as the value (e.g `my profile` would have the `id`: `9d9041f7-e535-5daa-972f-71cd20fb3855`).
            You cannot modify a profile once it is created. If you need to make changes, you should create another profile with the changes made. If it is essential that the same `name` value be used, then you must first delete the profile in order to recreate it.
            """
        ),
        responses={400: DEFAULT_400_ERROR, 200: ProfileSerializer}
    ),
    destroy=extend_schema(
        summary="Delete a profile",
        description=textwrap.dedent(
            """
            Delete an existing profile. Note, we would advise against deleting a Profile because any Files it has been used with will still refer to this ID. If it is deleted, you will not be able to see the profile settings used. Instead, it is usually better to just recreate a Profile with a new name.
            """
        ),
        responses={404: DEFAULT_404_ERROR, 204: None}
    ),
)
class ProfileView(viewsets.ModelViewSet):
    openapi_tags = ["Profiles"]
    serializer_class = ProfileSerializer
    http_method_names = ["get", "post", "delete"]
    pagination_class = Pagination("profiles")
    lookup_url_kwarg = 'profile_id'
    openapi_path_params = [
        OpenApiParameter(
            lookup_url_kwarg, location=OpenApiParameter.PATH, type=OpenApiTypes.UUID, description="The `id` of the Profile."
        )
    ]

    ordering_fields = ["name", "created"]
    ordering = "created_descending"
    filter_backends = [DjangoFilterBackend, Ordering]

    class filterset_class(FilterSet):
        name = Filter(
            label="Searches Profiles by their name. Search is wildcard. For example, `ip` will return Profiles with names `ip-extractions`, `ips`, etc.",
            lookup_expr="search"
            )

    def get_queryset(self):
        return Profile.objects


##


class txt2stixView(mixins.RetrieveModelMixin,
                           mixins.ListModelMixin, viewsets.GenericViewSet):
    serializer_class = Txt2stixExtractorSerializer
    lookup_url_kwarg = "id"
    
    def get_queryset(self):
        return None

    @classmethod
    def all_extractors(cls, types):
        return Txt2stixExtractorSerializer.all_extractors(types)

    def get_all(self):
        raise NotImplementedError("not implemented")
    

    def list(self, request, *args, **kwargs):
        page = self.paginate_queryset(list(self.get_all().values()))
        return self.get_paginated_response(page)

    def retrieve(self, request, *args, **kwargs):
        items = self.get_all()
        id_ = self.kwargs.get(self.lookup_url_kwarg)
        print(id_, self.lookup_url_kwarg, self.kwargs)
        item = items.get(id_)
        if not item:
            return response.Response(dict(message="item not found", code=404), status=404)
        return response.Response(item)

@extend_schema_view(
    list=extend_schema(
        summary="Search Extractors",
        description=textwrap.dedent(
            """
            Extractors are what extract the data from the text which is then converted into STIX objects.\n\n
            For more information see [txt2stix](https://github.com/muchdogesec/txt2stix/).
            """
        ),
        responses={400: DEFAULT_400_ERROR, 200: Txt2stixExtractorSerializer},
    ),
    retrieve=extend_schema(
        summary="Get an extractor",
        description="Get a specific Extractor.",
        responses={400: DEFAULT_400_ERROR, 404: DEFAULT_404_ERROR, 200: Txt2stixExtractorSerializer},
    ),
)
class ExtractorsView(txt2stixView):
    openapi_tags = ["Extractors"]
    lookup_url_kwarg = "extractor_id"
    openapi_path_params = [
        OpenApiParameter(
            lookup_url_kwarg, location=OpenApiParameter.PATH, type=OpenApiTypes.UUID, description="The `id` of the Extractor."
        )
    ]
    pagination_class = Pagination("extractors")

    def get_all(self):
        return self.all_extractors(["lookup", "pattern", "ai"])

@extend_schema_view(
    list=extend_schema(
        summary="Search for Whitelists",
        description=textwrap.dedent(
            """
            In many cases files will have IoC extractions that are not malicious. e.g. `google.com` (and thus they don't want them to be extracted). Whitelists provide a list of values to be compared to extractions. If a whitelist value matches an extraction, that extraction is removed. To see the values used in this Whitelist, visit the URL shown as the value for the `file` key.\n\n
            For more information see [txt2stix](https://github.com/muchdogesec/txt2stix/).
            """
        ),
        responses={400: DEFAULT_400_ERROR, 200: Txt2stixExtractorSerializer},
    ),
    retrieve=extend_schema(
        summary="Get a whitelist",
        description="Get a specific Whitelist. To see the values used in this Whitelist, visit the URL shown as the value for the `file` key",
        responses={400: DEFAULT_400_ERROR, 404: DEFAULT_404_ERROR, 200: Txt2stixExtractorSerializer},
    ),
)
class WhitelistsView(txt2stixView):
    lookup_url_kwarg = "whitelist_id"
    openapi_path_params = [
        OpenApiParameter(
            lookup_url_kwarg, location=OpenApiParameter.PATH, type=OpenApiTypes.UUID, description="The `id` of the Whitelist."
        )
    ]
    openapi_tags = ["Whitelists"]
    pagination_class = Pagination("whitelists")

    def get_all(self):
        return self.all_extractors(["whitelist"])

@extend_schema_view(
    list=extend_schema(
        summary="Search for aliases",
        description=textwrap.dedent(
            """
            Aliases replace strings in the blog post with values defined in the Alias. Aliases are applied before extractions. For example, an alias of `USA` with a value `United States` will change all records of `USA` in the blog post with `United States`. To see the values used in this Alias, visit the URL shown as the value for the `file` key\n\n
            For more information see [txt2stix](https://github.com/muchdogesec/txt2stix/).
            """
        ),
        responses={400: DEFAULT_400_ERROR, 200: Txt2stixExtractorSerializer},
    ),
    retrieve=extend_schema(
        summary="Get an Alias",
        description="Get a specific Alias. To see the values used in this Alias, visit the URL shown as the value for the `file` key",
        responses={400: DEFAULT_400_ERROR, 404: DEFAULT_404_ERROR, 200: Txt2stixExtractorSerializer},
    ),
)
class AliasesView(txt2stixView):
    openapi_tags = ["Aliases"]
    pagination_class = Pagination("aliases")

    lookup_url_kwarg = "alias_id"

    openapi_path_params = [
        OpenApiParameter(
            lookup_url_kwarg, location=OpenApiParameter.PATH, type=OpenApiTypes.UUID, description="The `id` of the Alias."
        )
    ]

    def get_all(self):
        return self.all_extractors(["alias"])
