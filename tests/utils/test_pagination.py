import random

import pytest
from tests.utils.models import ModelForTesting
from dogesec_commons.utils.pagination import CursorPagination, CompositeCursorPagination
from datetime import UTC, datetime
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory
from base64 import b64decode


@pytest.mark.django_db
def test_cursor_pagination_can_handle_duplicates(client):
    D_COUNT = random.randrange(1000, 5000)
    E_COUNT = random.randrange(1000, 5000)
    F_COUNT = random.randrange(1000, 50_000)
    d = datetime(2020, 1, 1, tzinfo=UTC)
    e = datetime(2020, 5, 1, tzinfo=UTC)

    objects = ModelForTesting.objects.bulk_create(
        ModelForTesting(created=d, id=i) for i in range(D_COUNT)
    )
    objects += ModelForTesting.objects.bulk_create(
        ModelForTesting(created=e, id=i + D_COUNT) for i in range(E_COUNT)
    )
    objects += ModelForTesting.objects.bulk_create(
        ModelForTesting(
            created=datetime.fromtimestamp(
                random.randrange(int(d.timestamp()), int(e.timestamp())+999_999_999), tz=UTC
            ).replace(hour=0, minute=0, second=0, microsecond=0),
            id=i+E_COUNT+D_COUNT,
        )
        for i in range(F_COUNT)
    )

    pagination = CompositeCursorPagination(results_key="dates")
    pagination.ordering = ["-created", "-id"]

    result_ids = []

    factory = APIRequestFactory()
    queryset = ModelForTesting.objects.all()

    cursor = None
    cursors = list()
    PAGE_SIZE = 50

    while True:
        params = {"page_size": PAGE_SIZE}
        if cursor:
            params["cursor"] = cursor

        request = Request(factory.get("/", data=params))

        page = pagination.paginate_queryset(queryset, request)
        resp = pagination.get_paginated_response(page)

        result_ids.extend([obj.id for obj in resp.data["dates"]])

        cursor = resp.data.get("next")

        if not cursor:
            break
        else:
            print(b64decode(cursor.encode("utf-8")))
            cursors.append(cursor)
    assert len(set(result_ids)) == len(result_ids)
    assert len(result_ids) == len(objects)
