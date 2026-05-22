from django.http import HttpRequest
import pytest
from tests.utils.models import ModelForTesting
from dogesec_commons.utils.pagination import CursorPagination
from datetime import datetime
from rest_framework import request, viewsets
from urllib.parse import parse_qs, urlparse
from rest_framework.test import APIRequestFactory


@pytest.mark.django_db
def test_cursor_pagination_can_handle_duplicates(client):
    d = datetime(2020, 1, 1)
    objects = ModelForTesting.objects.bulk_create(
        ModelForTesting(created=d, id=i) for i in range(2000)
    )


    factory = APIRequestFactory()

    result_ids = []
    cursor = None

    while True:
        r = request.Request(HttpRequest())
        r._request.META['HTTP_HOST'] = 'test'
        if cursor:
            r.query_params.update(cursor=cursor)

        pagination = CursorPagination(results_key="dates")

        result = pagination.paginate_queryset(
            ModelForTesting.objects.all(),
            r,
        )

        result_ids.extend([k.id for k in result])

        next_url = pagination.get_next_link()

        if not next_url:
            break

        cursor = parse_qs(urlparse(next_url).query)["cursor"][0]

    assert len(set(result_ids)) == len(result_ids), "found duplicates"
    assert len(result_ids) == 2000, "some items are missing"
    

