import pytest
from tests.utils.models import TestModel
from dogesec_commons.utils.pagination import CursorPagination
from datetime import datetime
from rest_framework import viewsets


@pytest.mark.django_db
def test_cursor_pagination_can_handle_duplicates(client):
    d = datetime(2020, 1, 1)
    objects = TestModel.objects.bulk_create(
        TestModel(created=d, id=i) for i in range(2000)
    )

    pagination = CursorPagination(results_key="dates")

    result_ids = []

    # TODO: paginate through the entire queryset and add the id to result_ids

    assert len(set(result_ids)) == len(result_ids)
    assert len(result_ids) == 2000
    

