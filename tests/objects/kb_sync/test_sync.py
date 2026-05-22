import os
from unittest.mock import patch

import pytest

from dogesec_commons.objects.helpers import ArangoDBHelper

from dogesec_commons.objects.kb_sync.sync import (
    KNOWLEDGEBASE_TYPE_MAPPING,
    get_existing_object_ids,
    make_updates_on_collection,
    run_on_kb_and_collection,
    run_on_collections,
)
from tests.objects.utils import make_s2a_uploads
from dogesec_commons.objects.kb_sync.retriever import STIXObjectRetriever


TEST_COLLECTION_1 = "test_kb_sync_collection_1_vertex_collection"
TEST_COLLECTION_2 = "test_kb_sync_collection_2_vertex_collection"


@pytest.fixture
def helper():
    helper = ArangoDBHelper("", None)
    db = helper.db
    try:
        db.create_collection(TEST_COLLECTION_2)
        db.create_collection(TEST_COLLECTION_1)
    except:
        pass
    return helper

@pytest.fixture
def kb_sync_test_data(helper):
    db = helper.db
    col = db.collection(TEST_COLLECTION_1)
    col_trunc = db.collection(TEST_COLLECTION_2)

    col.truncate()
    col_trunc.truncate()

    col.insert_many(
        [
            # CVE duplicates
            {
                "_key": "cve1_a",
                "id": "vulnerability--cve-1",
                "type": "vulnerability",
                "name": "CVE-1-old",
                "_record_md5_hash": "old-cve-copy",
            },
            {
                "_key": "cve1_b",
                "id": "vulnerability--cve-1",
                "type": "vulnerability",
                "name": "CVE-1-old",
                "_record_md5_hash": "new-cve-copy",
            },
            {
                "_key": "cve2",
                "id": "vulnerability--cve-2",
                "type": "vulnerability",
                "name": "CVE-2",
            },

            # CWE
            {
                "_key": "cwe1",
                "id": "weakness--1",
                "type": "weakness",
                "name": "CWE-79",
            },

            # Location
            {
                "_key": "loc1",
                "id": "location--1",
                "type": "location",
                "name": "Nigeria",
            },
            {
                "_key": "loc2",
                "id": "location--2",
                "type": "location",
                "name": "Ghana",
            },

            # CAPEC
            {
                "_key": "capec1",
                "id": "attack-pattern--capec-1",
                "type": "attack-pattern",
                "external_references": [
                    {"source_name": "capec", "external_id": "CAPEC-1"}
                ],
            },

            # ATLAS
            {
                "_key": "atlas1",
                "id": "attack-pattern--atlas-1",
                "type": "attack-pattern",
                "external_references": [
                    {"source_name": "mitre-atlas", "external_id": "AML.T0001"}
                ],
            },

            # DISARM
            {
                "_key": "disarm1",
                "id": "attack-pattern--disarm-1",
                "type": "attack-pattern",
                "external_references": [
                    {"source_name": "DISARM", "external_id": "D-1"}
                ],
            },

            # Sector
            {
                "_key": "sector1",
                "id": "identity--sector-1",
                "type": "identity",
                "external_references": [
                    {"source_name": "sector2stix", "external_id": "energy"}
                ],
            },

            # Enterprise attack
            {
                "_key": "ent1",
                "id": "attack-pattern--enterprise-1",
                "type": "attack-pattern",
                "x_mitre_domains": ["enterprise-attack"],
            },

            # Mobile attack
            {
                "_key": "mob1",
                "id": "attack-pattern--mobile-1",
                "type": "attack-pattern",
                "x_mitre_domains": ["mobile-attack"],
            },

            # ICS attack
            {
                "_key": "ics1",
                "id": "attack-pattern--ics-1",
                "type": "attack-pattern",
                "x_mitre_domains": ["ics-attack"],
            },

            # Mixed domains
            {
                "_key": "mix1",
                "id": "attack-pattern--mixed-domains",
                "type": "attack-pattern",
                "x_mitre_domains": ["enterprise-attack", "mobile-attack"],
            },

            # Noise
            {
                "_key": "noise1",
                "id": "attack-pattern--noise-1",
                "type": "attack-pattern",
                "x_mitre_domains": ["noise"],
            },
        ],
    )

@pytest.mark.parametrize(
    ("knowledgebase_type", "expected_ids"),
    [
        (
            "cve",
            {
                "vulnerability--cve-1",
                "vulnerability--cve-2",
            },
        ),
        (
            "cwe",
            {
                "weakness--1",
            },
        ),
        (
            "location",
            {
                "location--1",
                "location--2",
            },
        ),
        (
            "capec",
            {
                "attack-pattern--capec-1",
            },
        ),
        (
            "atlas",
            {
                "attack-pattern--atlas-1",
            },
        ),
        (
            "disarm",
            {
                "attack-pattern--disarm-1",
            },
        ),
        (
            "sector",
            {
                "identity--sector-1",
            },
        ),
        (
            "enterprise-attack",
            {
                "attack-pattern--enterprise-1",
                "attack-pattern--mixed-domains",
            },
        ),
        (
            "mobile-attack",
            {
                "attack-pattern--mobile-1",
                "attack-pattern--mixed-domains",
            },
        ),
        (
            "ics-attack",
            {
                "attack-pattern--ics-1",
            },
        ),
    ],
)
def test_get_existing_object_ids_filters(
    kb_sync_test_data,
    knowledgebase_type,
    expected_ids,
):
    ids = get_existing_object_ids(
        collection_name=TEST_COLLECTION_1,
        knowledgebase_type=knowledgebase_type,
    )

    assert set(ids) == expected_ids



def test_noise_objects_never_match_any_filter(
    kb_sync_test_data,
):
    forbidden_ids = {
        "attack-pattern--noise-1",
        "ipv4-addr--1",
    }

    for knowledgebase_type in KNOWLEDGEBASE_TYPE_MAPPING:
        returned_ids = get_existing_object_ids(
            collection_name=TEST_COLLECTION_1,
            knowledgebase_type=knowledgebase_type,
        )

        assert not forbidden_ids.intersection(returned_ids)


def test_mixed_domain_object_matches_multiple_kb_types(
    kb_sync_test_data,
):
    enterprise_updates = get_existing_object_ids(
        collection_name=TEST_COLLECTION_1,
        knowledgebase_type="enterprise-attack",
    )

    mobile_updates = get_existing_object_ids(
        collection_name=TEST_COLLECTION_1,
        knowledgebase_type="mobile-attack",
    )

    assert "attack-pattern--mixed-domains" in enterprise_updates
    assert "attack-pattern--mixed-domains" in mobile_updates

def test_cve_duplicate_ids_all_updated(
    kb_sync_test_data,
    helper,
):
    target_id = "vulnerability--cve-1"

    updates = {
        target_id: {
            "id": target_id,
            "type": "vulnerability",
            "name": "UPDATED-CVE-NAME",
            "_kb_update_time": 88888,
        }
    }

    updated_count = make_updates_on_collection(
        TEST_COLLECTION_1,
        updates,
    )

    # assert updated_count == 2

    docs = helper.execute_query(
        """
FOR doc IN @@collection
FILTER doc.id == @id
RETURN doc
        """,
        bind_vars={
            "@collection": TEST_COLLECTION_1,
            "id": target_id,
        },
        paginate=False,
    )

    # assert len(docs) == 2

    assert all(
        doc["name"] == "UPDATED-CVE-NAME"
        for doc in docs
    )

    assert all(
        doc["_kb_update_time"] == 88888
        for doc in docs
    )

    markers = {
        doc["_record_md5_hash"]
        for doc in docs
    }

    assert markers == {
        "old-cve-copy",
        "new-cve-copy",
    }


def test_make_updates_returns_zero_for_missing_ids(
    kb_sync_test_data,
):
    updated_count = make_updates_on_collection(
        TEST_COLLECTION_1,
        {
            "does-not-exist": {
                "id": "does-not-exist",
                "type": "vulnerability",
            }
        },
    )

    assert updated_count == 0


def test_run_on_kb_and_collection(
    kb_sync_test_data,
    fake_retrieve
):
    progress_calls = []

    def callback(**kwargs):
        progress_calls.append(kwargs)

    processed_count, updated_count = run_on_kb_and_collection(
        collection_name=TEST_COLLECTION_1,
        knowledgebase_type="cve",
        update_time=12345,
        progress_callback=callback,
    )

    assert processed_count > 0
    assert updated_count > 0

    assert progress_calls

    assert progress_calls[-1]["processed_count"] == processed_count
    assert progress_calls[-1]["updated_count"] == updated_count


def test_progress_callback_tracks_global_progress(
    kb_sync_test_data,
    fake_retrieve
):
    progress_calls = []

    def callback(**kwargs):
        progress_calls.append(kwargs)

    processed_count, updated_count = run_on_collections(
        vertex_collection_names=[
            TEST_COLLECTION_1,
        ],
        knowledgebase_types=[
            "cve",
            "enterprise-attack",
        ],
        progress_callback=callback,
    )

    assert progress_calls

    processed_values = [
        call["processed_count"]
        for call in progress_calls
    ]

    updated_values = [
        call["updated_count"]
        for call in progress_calls
    ]

    assert processed_values == sorted(processed_values)
    assert updated_values == sorted(updated_values)

    assert processed_values[-1] == processed_count
    assert updated_values[-1] == updated_count


def test_invalid_knowledgebase_type_raises(
    kb_sync_test_data,
):
    with pytest.raises(ValueError):
        run_on_collections(
            vertex_collection_names=[
                TEST_COLLECTION_1,
            ],
            knowledgebase_types=[
                "not-real",
            ],
        )


def test_default_knowledgebase_types_uses_all_types(
    kb_sync_test_data,
    fake_retrieve,
):
    processed_count, updated_count = run_on_collections(
        vertex_collection_names=[
            TEST_COLLECTION_1,
        ],
        knowledgebase_types=None,
    )

    assert processed_count > 0
    assert updated_count > 0


def test_empty_collection_list_returns_zero(
    kb_sync_test_data,
):
    processed_count, updated_count = run_on_collections(
        vertex_collection_names=[],
        knowledgebase_types=["cve"],
    )

    assert processed_count == 0
    assert updated_count == 0

@pytest.fixture
def fake_retrieve():
    os.environ.update(
        VULMATCH_BASE_URL='1',
        CTIBUTLER_BASE_URL='1',
    )
    def fake_object(_, url: str, *a):
        _, _, ids = url.partition('=')
        for id in ids.split(','):
            yield dict(id=id, modified=True)
    with patch.object(STIXObjectRetriever, 'retrieve_objects', fake_object):
        yield