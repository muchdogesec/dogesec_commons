from .models import Profile
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter
from drf_spectacular.types import OpenApiTypes
from ..utils import Pagination, Ordering

from rest_framework import viewsets, response, mixins, exceptions
from django_filters.rest_framework import DjangoFilterBackend, FilterSet, Filter, BooleanFilter
from .serializers import DEFAULT_400_ERROR, DEFAULT_404_ERROR, Txt2stixExtractorSerializer
from django.forms import NullBooleanField

from .serializers import ProfileSerializer

from drf_spectacular.utils import extend_schema, extend_schema_view
import django.db.models.deletion
import textwrap

EXTRACTOR_TYPES = ["lookup", "pattern", "ai"]

@extend_schema_view(
    list=extend_schema(
        summary="Search profiles",
        description=textwrap.dedent(
            """
            Profiles determine how txt2stix processes the text in each File. A profile consists of extractors. You can search for existing profiles here.
            """
        ),
        responses={400: DEFAULT_400_ERROR, 200: ProfileSerializer},
    ),
    retrieve=extend_schema(
        summary="Get a profile",
        description=textwrap.dedent(
            """
            View the configuration of an existing profile. Note, existing profiles cannot be modified.
            """
        ),
        responses={400: DEFAULT_400_ERROR, 404: DEFAULT_404_ERROR, 200: ProfileSerializer}
    ),
    create=extend_schema(
        summary="Create a new profile",
        description=textwrap.dedent(
            """
            Add a new Profile that can be applied to new Files. A profile consists of extractors. You can find available extractors via their respective endpoints.

            The following key/values are accepted in the body of the request:

            * `name` (required - must be unique)
            * `identity_id` (optional): a STIX Identity ID that you want to use to create the profile. Pass the full identity ID, e.g. `identity--de9fb9bd-7895-4b23-aa03-49250d9263c9`
            * `ai_create_attack_flow` (optional, boolean): default is `true`. passing as `true` will prompt the AI model (the same entered for `ai_settings_relationships`) to generate an [Attack Flow](https://center-for-threat-informed-defense.github.io/attack-flow/) for the MITRE ATT&CK extractions to define the logical order in which they are being described. You must pass `--ai_settings_relationships` for this to work.
            * `ai_summary_provider` (optional, AI provider:model): you can also generate a summary of the files this profile is linked to using an AI model. If not passed, no summary will be generated. Pass in format `"provider:model"` e.g. `"openai:gpt-4o"`.
            * `ai_content_check_provider` (optional, AI provider:model): Setting a value will get the AI to try and classify the text in the input to 1) determine if it is talking about threat intelligence, and 2) what type of threat intelligence it is talking about. For context, we use this to filter out non-threat intel posts in Obstracts Web (note, we don't filter in this way Stixify Web) using `always_extract` in dogesec_commons to reduce the cost of AI models and make them easier to search through classifications.  You pass `provider:model` (e.g. `"openai:gpt-4o"`) with this flag to determine the AI model you wish to use to perform the check. 
            * `extract_text_from_image` (required - boolean): whether to convert the images found in a blog to text. Requires a Google Vision key to be set. This is a [file2txt](https://github.com/muchdogesec/file2txt) setting.
            * `defang` (required - boolean): whether to defang the observables in the blog. e.g. turns `1.1.1[.]1` to `1.1.1.1` for extraction. This is a [file2txt](https://github.com/muchdogesec/file2txt) setting.
            * `ignore_image_refs` (optional, default `true`): whether to ignore embedded image references. This is a [txt2stix](https://github.com/muchdogesec/txt2stix/) setting.
            * `ignore_link_refs` (optional, default `true`): whether to ignore embedded link references. This is a [txt2stix](https://github.com/muchdogesec/txt2stix/) setting.
            * `extractions` (required - at least one extraction ID): can be obtained from the GET Extractors endpoint. This is a [txt2stix](https://github.com/muchdogesec/txt2stix/) setting.
            * `ai_settings_extractions` (required if AI extraction used, AI provider:model): A list of AI providers and models to be used for extraction in format `["provider:model","provider:model"]` e.g. `["openai:gpt-4o"]`. This is a [txt2stix](https://github.com/muchdogesec/txt2stix/) setting.
            * `ignore_extraction_boundary` (optional, default `false`): defines if a string boundary can generate multiple extractions (e.g. `url`, `domain`, etc). Setting to `true` will allow multiple extractions from the same string. This is a [txt2stix](https://github.com/muchdogesec/file2txt) setting.
            * `relationship_mode` (required): either `ai` or `standard`. Required AI provider to be configured if using `ai` mode. This is a [txt2stix](https://github.com/muchdogesec/txt2stix/) setting.
            * `ai_settings_relationships` (required if AI relationship used, AI provider:model): An AI provider and models to be used for relationship generation in format `"provider:model"` e.g. `"openai:gpt-4o"`. This is a [txt2stix](https://github.com/muchdogesec/txt2stix/) setting.
            * `generate_pdf` (optional, boolean): default is `false` will generate a PDF of the input if set to true 
            * `ignore_embedded_relationships` (optional, default: false): boolean, if `true` passed, this will stop ANY embedded relationships from being generated. This applies for all object types (SDO, SCO, SRO, SMO). If you want to target certain object types see `ignore_embedded_relationships_sro` and `ignore_embedded_relationships_sro` flags. This is a [stix2arango](https://github.com/muchdogesec/stix2arango) setting.
            * `ignore_embedded_relationships_sro` (optional, default: false): boolean, if `true` passed, will stop any embedded relationships from being generated from SRO objects (`type` = `relationship`). This is a [stix2arango](https://github.com/muchdogesec/stix2arango) setting.
            * `ignore_embedded_relationships_smo` (optional, default: false): boolean, if `true` passed, will stop any embedded relationships from being generated from SMO objects (`type` = `marking-definition`, `extension-definition`, `language-content`). This is a [stix2arango](https://github.com/muchdogesec/stix2arango) setting.

            A profile `id` is generated using a UUIDv5. The namespace used is is set using the `STIXIFIER_NAMESPACE` in dogesec tools, and the `name+identity_id` is used as the value (e.g a namespace of `9779a2db-f98c-5f4b-8d08-8ee04e02dbb5` and value `my profile+identity--de9fb9bd-7895-4b23-aa03-49250d9263c9` would have the `id`: `05004944-0eff-507e-8ef8-9ebdd043a51b`). Note, the name

            You cannot modify a profile once it is created. If you need to make changes, you should create another profile with the changes made. If it is essential that the same `name` + `identity_id` value be used, then you must first delete the profile in order to recreate it.
            """
        ),
        responses={400: DEFAULT_400_ERROR, 200: ProfileSerializer}
    ),
    destroy=extend_schema(
        summary="Delete a profile",
        description=textwrap.dedent(
            """
            Delete an existing profile.

            Note: it is not currently possible to delete a profile that is referenced in an existing object. You must delete the objects linked to the profile first.
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
            help_text="Searches Profiles by their `name`. Search is wildcard. For example, `ip` will return Profiles with names `ip-extractions`, `ips`, etc.",
            lookup_expr="icontains"
            )
        identity_id = Filter(
            help_text="filter the results by the identity that created the Profile. Use a full STIX identity ID, e.g. `identity--de9fb9bd-7895-4b23-aa03-49250d9263c9`"
        )

    def get_queryset(self):
        return Profile.objects
    
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
            Extractors are what extract the data from the text which is then converted into STIX objects.

            For more information see [txt2stix](https://github.com/muchdogesec/txt2stix/).
            """
        ),
        responses={400: DEFAULT_400_ERROR, 200: Txt2stixExtractorSerializer},
    ),
    retrieve=extend_schema(
        summary="Get an extractor",
        description=textwrap.dedent(
            """
            Get a specific Extractor.
            """
        ),
        responses={400: DEFAULT_400_ERROR, 404: DEFAULT_404_ERROR, 200: Txt2stixExtractorSerializer},
    ),
)
class ExtractorsView(txt2stixView):
    openapi_tags = ["Extractors"]
    lookup_url_kwarg = "extractor_id"
    openapi_path_params = [
        OpenApiParameter(
            lookup_url_kwarg, location=OpenApiParameter.PATH, type=OpenApiTypes.STR, description="The `id` of the Extractor."
        )
    ]
    pagination_class = Pagination("extractors")
    filter_backends = [DjangoFilterBackend]


    class filterset_class(FilterSet):
        type = Filter(choices=[(extractor, extractor) for extractor in EXTRACTOR_TYPES], help_text="Filter Extractors by their `type`")
        name = Filter(help_text="Filter extractors by `name`. Is wildcard search so `ip` will return `ipv4`, `ipv6`, etc.)")
        web_app = BooleanFilter(help_text="filters on `dogesec_web` property in txt2stix filter.\nuse case is, web app can set this to true to only show extractors allowed in web app")

    def get_all(self):
        types = EXTRACTOR_TYPES
        if type := self.request.GET.get('type'):
            types = type.split(',')

        extractors = self.all_extractors(types)

        if name := self.request.GET.get('name', '').lower():
            extractors = {slug: extractor for slug, extractor in extractors.items() if name in extractor['name'].lower()}

        webapp_filter = NullBooleanField.to_python(..., self.request.GET.get('web_app', ''))
        if webapp_filter != None:
            extractors = {slug: extractor for slug, extractor in extractors.items() if extractor.get('dogesec_web') == webapp_filter}
        return extractors