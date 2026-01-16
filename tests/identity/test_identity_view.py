import uuid
from stix2.utils import format_datetime, parse_into_datetime
import pytest
from dogesec_commons.identity import models, serializers

@pytest.fixture
def identity(db):
    """Create a test identity (feed owner)."""
    identity_s = serializers.IdentitySerializer(
        data=dict(
            id="identity--73faab8f-9a95-4417-a2db-c1a8b73c7029",
            name="Test Identity",
            identity_class="organization",
            sectors=["technology"],
            created="2020-01-01T00:00:00.000Z",
            modified="2020-01-01T00:00:00.000Z",
        )
    )
    identity_s.is_valid(raise_exception=True)
    identity: models.Identity = identity_s.save()
    identity.refresh_from_db()
    yield identity

@pytest.fixture(autouse=True)
def always_use_db(db):
    """Ensure all tests use the database."""
    pass

def test_update_identity_bad_data(client, identity):
    data = {
        "id": "identity--" + str(uuid.uuid4()),
        "name": "Should Fail",
        "created": "2025-10-09T01:01:01.001Z",
    }

    resp = client.put(
        f"/identities/{identity.id}/",
        data,
        content_type="application/json",
    )
    assert resp.status_code == 400
    errors = resp.json()["details"]
    assert errors["id"] == ["Cannot modify 'id' of an existing Identity."]


def test_update_identity_good_data(client, identity):
    data = {
        "name": "Updated Name",
        "sectors": ["finance", "technology"],
    }

    resp = client.put(
        f"/identities/{identity.id}/",
        data,
        content_type="application/json",
    )
    assert resp.status_code == 200
    updated_identity = resp.json()
    assert updated_identity["name"] == "Updated Name"
    assert updated_identity["sectors"] == ["finance", "technology"]
    assert updated_identity["id"] == identity.id
    assert parse_into_datetime(updated_identity["created"]) == identity.created


def test_create_identity(client):
    data = {
        "name": "New Identity",
        "identity_class": "individual",
        "sectors": ["healthcare"],
        "id": "identity--" + str(uuid.uuid4()),
    }

    resp = client.post(
        "/identities/",
        data,
        content_type="application/json",
    )
    assert resp.status_code == 201, resp.content
    new_identity = resp.json()
    assert new_identity["name"] == "New Identity"
    assert new_identity["identity_class"] == "individual"
    assert new_identity["sectors"] == ["healthcare"]
    assert new_identity["id"] == data["id"]
    assert new_identity["created"] == new_identity["modified"]


def test_create_identity_with_modified(client):
    data = {
        "name": "New Identity",
        "identity_class": "individual",
        "sectors": ["healthcare"],
        "id": "identity--" + str(uuid.uuid4()),
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2023-01-01T00:00:00.000Z",
    }

    resp = client.post(
        "/identities/",
        data,
        content_type="application/json",
    )
    assert resp.status_code == 201, resp.content
    new_identity = resp.json()
    assert new_identity["name"] == "New Identity"
    assert new_identity["identity_class"] == "individual"
    assert new_identity["sectors"] == ["healthcare"]
    assert new_identity["id"] == data["id"]
    assert new_identity["created"] == data["created"]
    assert new_identity["modified"] == data["modified"]


def test_put_identity_updates_modified(client, identity):
    payload = {
        "name": "Updated Identity",
        "identity_class": "individual",
        "contact_information": "updated-email@dogesec.com",
    }
    resp = client.put(
        f"/identities/{identity.id}/",
        payload,
        content_type="application/json",
    )
    assert resp.status_code == 200, resp.content
    data = resp.json()
    assert (
        data["modified"] != data["created"]
    ), "modified timestamp should be updated on put"
    assert "sectors" not in data, "sectors should be removed if not in payload"
    assert data == {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--73faab8f-9a95-4417-a2db-c1a8b73c7029",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": data["modified"],
        "name": "Updated Identity",
        "identity_class": "individual",
        "contact_information": "updated-email@dogesec.com",
    }


def test_create_identity_unique_id(client, identity):
    data = {
        "id": identity.id,
        "name": "Duplicate ID Identity",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2020-01-01T00:00:00.000Z",
        "identity_class": "individual",
        "sectors": ["education"],
    }

    resp = client.post(
        "/identities/",
        data,
        content_type="application/json",
    )
    assert resp.status_code == 400
    errors = resp.json()["details"]
    assert errors["id"] == ["This field must be unique."]
