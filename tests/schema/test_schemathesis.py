import time
from urllib.parse import urlencode
import schemathesis
import pytest
from schemathesis.core.transport import Response as SchemathesisResponse
from dogesec_commons.identity.serializers import IdentitySerializer
from dogesec_commons.wsgi import application as wsgi_app
from rest_framework.response import Response as DRFResponse
from schemathesis.specs.openapi.checks import (
    negative_data_rejection,
    positive_data_acceptance,
)
from schemathesis.config import GenerationConfig
from hypothesis import strategies

schema = schemathesis.openapi.from_wsgi(
    "/api/schema/?format=json",
    wsgi_app,
)
schema.config.base_url = "http://localhost:8005/"
schema.config.generation = GenerationConfig(allow_x00=False)


@pytest.fixture(autouse=True)
def identities(db):
    identities = []
    for name, stix_id in [
        ("Test Identity 1", "identity--73faab8f-9a95-4417-a2db-c1a8b73c7029"),
        ("Test Identity 2", "identity--90b66c75-8439-4fe2-8a0b-f2e6ff0d00b6"),
    ]:
        identity_s = IdentitySerializer(
            data=dict(
                id=stix_id,
                name=name,
                identity_class="organization",
                sectors=["technology"],
                created="2020-01-01T00:00:00.000Z",
                modified="2020-01-01T00:00:00.000Z",
            )
        )
        identity_s.is_valid(raise_exception=True)
        identity = identity_s.save()
        identity.refresh_from_db()
        identities.append(identity)
    yield identities


@pytest.fixture(autouse=True)
def override_transport(monkeypatch, client):
    from schemathesis.transport.wsgi import WSGI_TRANSPORT, WSGITransport

    class Transport(WSGITransport):
        def __init__(self):
            super().__init__()
            self._copy_serializers_from(WSGI_TRANSPORT)

        @staticmethod
        def case_as_request(case):
            from schemathesis.transport.requests import REQUESTS_TRANSPORT
            import requests

            r_dict = REQUESTS_TRANSPORT.serialize_case(
                case,
                base_url=case.operation.base_url,
            )
            return requests.Request(**r_dict).prepare()

        def send(self, case: schemathesis.Case, *args, **kwargs):
            t = time.time()
            case.headers.pop("Authorization", "")
            serialized_request = WSGI_TRANSPORT.serialize_case(case)
            serialized_request.update(
                QUERY_STRING=urlencode(serialized_request["query_string"])
            )
            response: DRFResponse = client.generic(**serialized_request)
            elapsed = time.time() - t
            return SchemathesisResponse(
                response.status_code,
                headers={k: [v] for k, v in response.headers.items()},
                content=response.content,
                request=self.case_as_request(case),
                elapsed=elapsed,
                verify=True,
            )

    ## patch transport.get
    from schemathesis import transport

    monkeypatch.setattr(transport, "get", lambda _: Transport())


@pytest.mark.django_db(transaction=True)
@schema.given(
    identity_id=strategies.sampled_from(
        [
            "identity--73faab8f-9a95-4417-a2db-c1a8b73c7029",
            "identity--90b66c75-8439-4fe2-8a0b-f2e6ff0d00b6",
            "identity--89718333-15ec-4ffd-945e-831fe133f58c",
        ]
    )
)
@schema.parametrize()
def test_api(case: schemathesis.Case, **kwargs):
    for k, v in kwargs.items():
        if k in case.path_parameters:
            case.path_parameters[k] = v
    case.call_and_validate(
        excluded_checks=[negative_data_rejection, positive_data_acceptance]
    )
