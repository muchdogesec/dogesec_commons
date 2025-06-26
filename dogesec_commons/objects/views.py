from dogesec_commons.objects import conf
from dogesec_commons.utils.schemas import DEFAULT_400_RESPONSE
from .helpers import (
    OBJECT_TYPES,
    ArangoDBHelper,
    SCO_TYPES,
    SDO_TYPES,
    SMO_TYPES,
    SRO_SORT_FIELDS,
    SMO_SORT_FIELDS,
    SCO_SORT_FIELDS,
    SDO_SORT_FIELDS,
)
from drf_spectacular.utils import extend_schema_view, extend_schema, OpenApiParameter
from drf_spectacular.types import OpenApiTypes
from rest_framework import viewsets, exceptions, decorators
from rest_framework.response import Response

from django.conf import settings

import textwrap


class QueryParams:
    value = OpenApiParameter(
        "value",
        description=textwrap.dedent(
            """
            Search by the `value` field field of the SCO. This is the IoC. So if you're looking to retrieve a IP address by address you would enter the IP address here. Similarly, if you're looking for a credit card you would enter the card number here.
            Search is wildcard. For example, `1.1` will return SCOs with `value` fields; `1.1.1.1`, `2.1.1.2`, etc.
            If `value` field is named differently for the Object (e.g. `hash`) it will still be searched because these have been aliased to the `value` in the database search).
            """
        ),
    )
    sco_types = OpenApiParameter(
        "types",
        many=True,
        explode=False,
        description=textwrap.dedent(
            """
            Filter the results by one or more STIX SCO Object types
            """
        ),
        enum=SCO_TYPES,
    )
    post_id = OpenApiParameter(
        "post_id",
        description=textwrap.dedent(
            """
            Filter the results to only contain objects present in the specified Post ID. Get a Post ID using the Feeds endpoints.
            """
        ),
    )
    SCO_PARAMS = [
        value,
        sco_types,
        post_id,
        OpenApiParameter("sort", enum=SCO_SORT_FIELDS),
    ]

    name = OpenApiParameter(
        "name",
        description=textwrap.dedent(
            """
            Allows results to be filtered on the `name` field of the SDO. Search is wildcard. For example, `Wanna` will return SDOs with the `name`; `WannaCry`, `WannaSmile`, etc.
            """
        ),
    )
    labels = OpenApiParameter(
        "labels",
        description=textwrap.dedent(
            """
            Allows results to be filtered on each value in the `labels` field of the SDO. Each value in the `labels` list will be searched individually.
            Search is wildcard. For example, `needs` will return SDOs with `labels`; `need-attribution`, `needs-review`, etc. The value entered only needs to match one item in the `labels` list to return results.
            """
        ),
    )
    sdo_types = OpenApiParameter(
        "types",
        many=True,
        explode=False,
        description=textwrap.dedent(
            """
            Filter the results by one or more STIX Domain Object types
            """
        ),
        enum=SDO_TYPES,
    )

    SDO_PARAMS = [
        name,
        labels,
        sdo_types,
        OpenApiParameter("sort", enum=SDO_SORT_FIELDS),
    ]

    source_ref = OpenApiParameter(
        "source_ref",
        description=textwrap.dedent(
            """
            Filter the results on the `source_ref` fields. The value entered should be a full ID of a STIX SDO or SCO which can be obtained from the respective Get Object endpoints. This endpoint allows for graph traversal use-cases as it returns STIX `relationship` objects that will tell you what objects are related to the one entered (in the `target_ref` property).
            """
        ),
    )
    source_ref_type = OpenApiParameter(
        "source_ref_type",
        many=True,
        explode=False,
        description=textwrap.dedent(
            """
            Filter the results by the STIX object type in the `source_ref` field. Unlike the `source_ref` filter that requires a full STIX object ID, this filter allows for a more open search. For example, `attack-pattern` will return all `relationship` Objects where the `source_ref` contains the ID of an `attack-pattern` Object.
            """
        ),
    )
    target_ref = OpenApiParameter(
        "target_ref",
        description=textwrap.dedent(
            """
            Filter the results on the `target_ref` fields. The value entered should be a full ID of a STIX SDO or SCO which can be obtained from the respective Get Object endpoints. This endpoint allows for graph traversal use-cases as it returns STIX `relationship` objects that will tell you what objects are related to the one entered (in the `source_ref` property).
            """
        ),
    )
    target_ref_type = OpenApiParameter(
        "target_ref_type",
        many=True,
        explode=False,
        description=textwrap.dedent(
            """
            Filter the results by the STIX object type in the `target_ref` field. Unlike the `target_ref` filter that requires a full STIX object ID, this filter allows for a more open search. For example, `attack-pattern` will return all `relationship` Objects where the `target_ref` contains the ID of an `attack-pattern` Object.
            """
        ),
    )
    relationship_type = OpenApiParameter(
        "relationship_type",
        description=textwrap.dedent(
            """
            Filter the results on the `relationship_type` field. Search is wildcard. For example, `in` will return `relationship` objects with ``relationship_type`s; `found-in`, `located-in`, etc.
            """
        ),
    )
    include_embedded_refs = OpenApiParameter(
        "include_embedded_refs",
        description=textwrap.dedent(
            """
            If `ignore_embedded_relationships` is set to `false` in the POST request to download data, stix2arango will create SROS for embedded relationships (e.g. from `created_by_refs`). You can choose to show them (`true`) or hide them (`false`) using this parameter. Default value if not passed is `true`.
            """
        ),
        type=OpenApiTypes.BOOL,
    )

    SRO_PARAMS = [
        source_ref,
        source_ref_type,
        target_ref,
        target_ref_type,
        relationship_type,
        include_embedded_refs,
        OpenApiParameter("sort", enum=SRO_SORT_FIELDS),
    ]

    all_types = OpenApiParameter(
        "types",
        many=True,
        explode=False,
        description=textwrap.dedent(
            """
            Filter the results by one or more STIX Object types
            """
        ),
        enum=OBJECT_TYPES,
    )
    OBJECTS_PARAMS = [
        all_types,
    ]

    smo_types = OpenApiParameter(
        "types",
        many=True,
        explode=False,
        description=textwrap.dedent(
            """
            Filter the results by one or more STIX Object types
            """
        ),
        enum=SMO_TYPES,
    )
    SMO_PARAMS = [
        smo_types,
        OpenApiParameter("sort", enum=SMO_SORT_FIELDS),
    ]

    object_id_param = OpenApiParameter(
        "object_id",
        description="Filter by the STIX object ID. e.g. `ipv4-addr--ba6b3f21-d818-4e7c-bfff-765805177512`, `indicator--7bff059e-6963-4b50-b901-4aba20ce1c01`",
        type=OpenApiTypes.STR,
        location=OpenApiParameter.PATH,
    )

    visible_to = OpenApiParameter(
        "visible_to",
        description="Only show objects that are visible to the Identity `id` passed. e.g. passing `identity--b1ae1a15-6f4b-431e-b990-1b9678f35e15` would only show reports created by that identity (with any TLP level) or objects created by another identity ID but only if they are marked with `TLP:CLEAR` or `TLP:GREEN`.",
        type=OpenApiTypes.STR,
    )


@extend_schema_view(
    retrieve=extend_schema(
        summary="Get a STIX Object",
        description=textwrap.dedent(
            """
            Get a STIX Object by its ID
            """
        ),
        responses={200: ArangoDBHelper.STIX_OBJECT_SCHEMA, 404: DEFAULT_400_RESPONSE, 400: DEFAULT_400_RESPONSE},
        parameters=[QueryParams.object_id_param],
    ),
    bundle=extend_schema(
        summary="Get STIX Object's Bundle",
        description=textwrap.dedent(
            """
            Return all objects the STIX Object has a relationship to as a bundle of all objects.
            """
        ),
        responses=ArangoDBHelper.get_paginated_response_schema(),
        parameters=ArangoDBHelper.get_schema_operation_parameters()
        + [
            QueryParams.object_id_param,
            QueryParams.all_types,
            QueryParams.include_embedded_refs,
            QueryParams.visible_to,
        ],
    ),
)
class SingleObjectView(viewsets.ViewSet):
    lookup_url_kwarg = "object_id"
    openapi_tags = ["Objects"]
    lookup_value_regex = (
        r"[\w\-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    )

    def retrieve(self, request, *args, **kwargs):
        return ArangoDBHelper(conf.ARANGODB_DATABASE_VIEW, request).get_objects_by_id(
            kwargs.get(self.lookup_url_kwarg)
        )

    @decorators.action(detail=True, methods=["GET"])
    def bundle(self, request, *args, **kwargs):
        return ArangoDBHelper(conf.ARANGODB_DATABASE_VIEW, request).get_object_bundle(
            kwargs.get(self.lookup_url_kwarg)
        )


@extend_schema_view(
    reports=extend_schema(
        responses=ArangoDBHelper.get_paginated_response_schema(
            "reports",
            {
                "type": "object",
                "properties": {
                    "type": {
                        "example": "report",
                    },
                    "id": {
                        "example": "report--a86627d4-285b-5358-b332-4e33f3ec1075",
                    },
                },
                "additionalProperties": True,
            },
        ),
        parameters=ArangoDBHelper.get_schema_operation_parameters()
        + [QueryParams.object_id_param],
        summary="Get all Reports that contain this STIX Object",
        description=textwrap.dedent(
            """
            Return all reports the STIX Object has a Relationship to.
            """
        ),
    ),
    destroy_in_report=extend_schema(
        summary="Delete an Object from a Report",
        description=textwrap.dedent(
            """
            Occasionally txt2stix will create an erroneous extraction from a text document. This endpoint allows you to remove the STIX objects created for such extractions.

            This request will delete the object ID specified in the request, and ALL relationship objects that reference this Objects ID in either the `source_ref` or `target_ref` property of the relationship object.

            You can safely to run this request on SCOs that are seen in multiple reports. Whilst Obstracts shows a single SCO with the same value with the same STIX ID (e.g. `1.1.1.1`), in the database multiple versions of the same SCO object exist, one for each report (identified using the field `_stix2arango=<REPORT_ID`). All objects created during the processing of this report have this field too.

            **DANGER:** This action is irreversible. It also can create issues if not run carefully. For example, assume you have a connection from a report object as follows; Report -> Indicator -> IPv4. Should you delete the Indicator objects in this example, the IPv4 will no longer be directly connected to the report (though it will still appear in the report bundle, and the reports `object_refs` property).
            """
        ),
    ),
)
class ObjectsWithReportsView(SingleObjectView):
    @decorators.action(detail=True, methods=["GET"])
    def reports(self, request, *args, **kwargs):
        return ArangoDBHelper(
            conf.ARANGODB_DATABASE_VIEW, request, "reports"
        ).get_containing_reports(kwargs.get(self.lookup_url_kwarg))

    @decorators.action(
        detail=True,
        methods=["DELETE"],
        url_path=r"reports/(?P<report_id>report--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    )
    def destroy_in_report(
        self, request, *args, object_id=None, report_id=None, **kwargs
    ):
        return ArangoDBHelper(
            conf.ARANGODB_DATABASE_VIEW, request
        ).delete_report_object(report_id=report_id, object_id=object_id)


@extend_schema_view(
    list=extend_schema(
        responses=ArangoDBHelper.get_paginated_response_schema(),
        parameters=ArangoDBHelper.get_schema_operation_parameters()
        + QueryParams.SDO_PARAMS + [QueryParams.visible_to],
        summary="Search and filter STIX Domain Objects",
        description=textwrap.dedent(
            """
            Search for domain objects (aka TTPs). If you have the object ID already, you can use the base GET Objects endpoint.
            """
        ),
    ),
)
class SDOView(viewsets.ViewSet):
    skip_list_view = True
    openapi_tags = ["Objects"]

    def list(self, request, *args, **kwargs):
        return ArangoDBHelper(conf.ARANGODB_DATABASE_VIEW, request).get_sdos()


@extend_schema_view(
    list=extend_schema(
        responses=ArangoDBHelper.get_paginated_response_schema(),
        parameters=ArangoDBHelper.get_schema_operation_parameters()
        + QueryParams.SCO_PARAMS,
        summary="Search and filter STIX Cyber Observable Objects",
        description=textwrap.dedent(
            """
            Search for STIX Cyber Observable Objects (aka Indicators of Compromise). If you have the object ID already, you can use the base GET Objects endpoint.

            Note the `value` filter searches the following object properties;

            * `artifact.payload_bin`
            * `autonomous-system.number`
            * `bank-account.iban_number`
            * `bank-card.number`
            * `cryptocurrency-transaction.hash`
            * `cryptocurrency-wallet.hash`
            * `directory.path`
            * `domain-name.value`
            * `email-addr.value`
            * `email-message.body`
            * `file.name`
            * `ipv4-addr.value`
            * `ipv6-addr.value`
            * `mac-addr.value`
            * `mutex.value`
            * `network-traffic.protocols`
            * `phone-number.number`
            * `process.pid`
            * `software.name`
            * `url.value`
            * `user-account.display_name`
            * `user-agent.string`
            * `windows-registry-key.key`
            * `x509-certificate.subject`
            """
        ),
    ),
)
class SCOView(viewsets.ViewSet):
    skip_list_view = True
    openapi_tags = ["Objects"]

    def list(self, request, *args, **kwargs):
        matcher = {}
        if post_id := request.query_params.dict().get("post_id"):
            matcher["_obstracts_post_id"] = post_id
        return ArangoDBHelper(conf.ARANGODB_DATABASE_VIEW, request).get_scos(
            matcher=matcher
        )


@extend_schema_view(
    list=extend_schema(
        responses=ArangoDBHelper.get_paginated_response_schema(),
        parameters=ArangoDBHelper.get_schema_operation_parameters()
        + QueryParams.SMO_PARAMS,
        summary="Search and filter STIX Meta Objects",
        description=textwrap.dedent(
            """
            Search for meta objects. If you have the object ID already, you can use the base GET Objects endpoint.
            """
        ),
    )
)
class SMOView(viewsets.ViewSet):
    skip_list_view = True
    openapi_tags = ["Objects"]

    def list(self, request, *args, **kwargs):
        return ArangoDBHelper(conf.ARANGODB_DATABASE_VIEW, request).get_smos()


@extend_schema_view(
    list=extend_schema(
        responses=ArangoDBHelper.get_paginated_response_schema(),
        parameters=ArangoDBHelper.get_schema_operation_parameters()
        + QueryParams.SRO_PARAMS + [QueryParams.visible_to],
        summary="Search and filter STIX Relationship Objects",
        description=textwrap.dedent(
            """
            Search for relationship objects. This endpoint is particularly useful to search what Objects an SCO or SDO is linked to.
            """
        ),
    ),
)
class SROView(viewsets.ViewSet):
    skip_list_view = True
    openapi_tags = ["Objects"]

    def list(self, request, *args, **kwargs):
        return ArangoDBHelper(conf.ARANGODB_DATABASE_VIEW, request).get_sros()
