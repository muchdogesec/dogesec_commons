import random
import pytest
from unittest.mock import MagicMock, patch
from rest_framework.test import APIRequestFactory
from dogesec_commons.objects.helpers import positive_int, ArangoDBHelper


@pytest.mark.parametrize(
    "value,cutoff,default,expected",
    [
        ("10", None, 1, 10),
        ("-5", None, 1, 1),
        ("abc", None, 1, 1),
        ("50", 30, 1, 30),
        (None, None, 2, 2),
    ],
)
def test_positive_int(value, cutoff, default, expected):
    assert positive_int(value, cutoff, default) == expected



@patch("dogesec_commons.objects.helpers.ArangoDBHelper.client")
@pytest.mark.parametrize(
    "params",
    [
        dict(page=2, page_size=5),
        dict(page=5, page_size=51),
        dict(page=5, page_size=51),
        dict(page_size=51),
    ],
)
def test_get_page_params(mock_client, params):
    page, page_size = ArangoDBHelper.get_page_params(params)
    assert page == max(params.get("page", -9), 1)
    assert page_size == min(params.get("page_size", 50), 50)


@pytest.mark.parametrize(
    ["value", "expected"],
    [
        ("malware,file", ["malware", "file"]),
        ("malware", ["malware"]),
        ("", []),
    ],
)
def test_query_as_array(value, expected):
    request = MagicMock()
    request.query_params.dict.return_value = {"types": value}
    helper = ArangoDBHelper("collection", request)
    result = helper.query_as_array("types")
    assert result == expected


@pytest.mark.parametrize(
    ["value", "expected"],
    [
        ("true", True),
        ("True", True),
        ("1", True),
        ("y", True),
        ("0", False),
        ("false", False),
        ("False", False),
        ("no", False),
    ],
)
def test_query_as_bool(value, expected):
    request = MagicMock()
    request.query_params.dict.return_value = {"include_embedded_refs": value}
    helper = ArangoDBHelper("collection", request)
    result = helper.query_as_bool("include_embedded_refs", default=None)
    assert result is expected


def test_query_as_bool_default():
    request = MagicMock()
    request.query_params.dict.return_value = {"exists": "false"}
    helper = ArangoDBHelper("collection", request)
    assert helper.query_as_bool("exists", default=True) == False
    assert helper.query_as_bool("badkey", default=False) == False
    assert helper.query_as_bool("badkey", default=True) == True


@pytest.mark.parametrize(
    "query_sort,sort_options,customs,doc_name,expected",
    [
        # Case 1: Valid sort field, ascending
        (
            "name_ascending",
            ["name_ascending", "date_descending"],
            {},
            "doc",
            "SORT doc.name ASC",
        ),
        # Case 2: Valid sort field, descending
        (
            "date_descending",
            ["name_ascending", "date_descending"],
            {},
            "doc",
            "SORT doc.date DESC",
        ),
        # Case 3: Sort not in options, should return empty string
        ("invalid_sort", ["name_ascending", "date_descending"], {}, "doc", ""),
        # Case 4: Custom field mapping used
        (
            "score_descending",
            ["score_descending"],
            {"score": "custom.score_field"},
            "doc",
            "SORT custom.score_field DESC",
        ),
        # Case 5: Different doc_name prefix
        ("rank_ascending", ["rank_ascending"], {}, "item", "SORT item.rank ASC"),
    ],
)
def test_get_sort_stmt(query_sort, sort_options, customs, doc_name, expected):
    request = MagicMock()
    request.query_params.dict.return_value = {"sort": query_sort}
    helper = ArangoDBHelper("collection", request)
    helper.query = {"sort": query_sort}
    result = helper.get_sort_stmt(sort_options, customs=customs, doc_name=doc_name)
    assert result == expected


def test_get_offset_and_count():
    helper = ArangoDBHelper("collection", MagicMock())
    offset, count = helper.get_offset_and_count(10, 3)
    assert offset == 20
    assert count == 10


def test_get_paginated_response():
    data = [{"name": "Item1"} for _ in range(random.randint(5, 10))]
    response = ArangoDBHelper.get_paginated_response(
        data, page_number=2, page_size=3, full_count=10
    )
    assert response.data["page_size"] == 3
    assert response.data["page_results_count"] == len(data)
    assert response.data["page_number"] == 2
    assert response.data["total_results_count"] == 10
    assert response.data["objects"] == data
