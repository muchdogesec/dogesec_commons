from datetime import UTC, datetime
import random
from unittest.mock import MagicMock

import pytest

from dogesec_commons.utils.ordering import Ordering
from tests.utils.models import ModelForTesting


def build_view(request, ordering_fields, default_ordering):
    view = MagicMock()
    view.ordering_fields = ordering_fields
    view.ordering = default_ordering
    view.request = request
    return view


def build_request(query_params):
    request = MagicMock()
    request.query_params = query_params
    return request


@pytest.fixture
def populated_queryset(db):
    f_count = random.randrange(1000, 5000)

    d = datetime(2020, 1, 1, tzinfo=UTC)
    e = datetime(2020, 5, 1, tzinfo=UTC)
    ModelForTesting.objects.bulk_create(
        ModelForTesting(
            created=datetime.fromtimestamp(
                random.randrange(int(d.timestamp()), int(e.timestamp()) + 999_999_999),
                tz=UTC,
            ),
            id=i,
        )
        for i in range(f_count)
    )

    return ModelForTesting.objects.all()


def test_uses_default_ordering_when_no_sort_param(populated_queryset):
    ordering_filter = Ordering()
    req = build_request({})
    view = build_view(req, ['created', 'id'], "created_descending")

    ordering = ordering_filter.get_ordering(req, populated_queryset, view)
    assert ordering == ['-created']

    ordering_filter.filter_queryset(req, populated_queryset, view)


def test_applies_explicit_sort_parameter(populated_queryset):
    ordering_filter = Ordering()
    req = build_request({'sort': 'id_ascending'})
    view = build_view(req, ['created', 'id'], "created_descending")

    ordering = ordering_filter.get_ordering(req, populated_queryset, view)
    assert ordering == ['id']

    ordering_filter.filter_queryset(req, populated_queryset, view)


def test_resolves_mapped_ordering_key_to_fields(populated_queryset):
    ordering_filter = Ordering()
    req = build_request({'sort': 'created_die'})

    ordering_fields = {
        'created_die': ['id', '-created'],
        'created_asc': ['created', 'id'],
    }
    view = build_view(req, ordering_fields, "created_descending")

    ordering = ordering_filter.get_ordering(req, populated_queryset, view)
    assert ordering == ['id', '-created']

    ordering_filter.filter_queryset(req, populated_queryset, view)


def test_resolves_mapped_ordering_string_to_single_field(populated_queryset):
    ordering_filter = Ordering()
    req = build_request({'sort': 'created_die'})

    ordering_fields = {
        'created_die': 'created',
        'created_asc': ['created', 'id'],
    }
    view = build_view(req, ordering_fields, "created_descending")

    ordering = ordering_filter.get_ordering(req, populated_queryset, view)
    assert ordering == ['created']

    ordering_filter.filter_queryset(req, populated_queryset, view)