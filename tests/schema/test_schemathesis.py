import time
from urllib.parse import urlencode
import schemathesis
import pytest
from schemathesis.core.transport import Response as SchemathesisResponse
from dogesec_commons.wsgi import application as wsgi_app
from rest_framework.response import Response as DRFResponse
from schemathesis.specs.openapi.checks import (
    negative_data_rejection,
    positive_data_acceptance,
)
from schemathesis.config import GenerationConfig

schema = schemathesis.openapi.from_wsgi(
    "/api/schema/?format=json",
    wsgi_app,
)
schema.config.base_url = "http://localhost:8005/"
schema.config.generation = GenerationConfig(allow_x00=False)


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
@schema.parametrize()
def test_api(case: schemathesis.Case):
    case.call_and_validate(
        excluded_checks=[negative_data_rejection, positive_data_acceptance]
    )
