import uuid
import pytest
from dogesec_commons.stixifier.serializers import (
    validate_model,
    validate_stix_id,
    ProfileSerializer,
)
from rest_framework.validators import ValidationError


def test_validate_model():
    assert validate_model("openai") == "openai"
    assert validate_model("") == None
    with pytest.raises(ValidationError):
        validate_model("random:10s")


def test_validate_stix_id():
    id = str(uuid.uuid4())
    assert validate_stix_id("report--" + id, "report") == "report--" + id
    assert validate_stix_id("indicator--" + id, "indicator") == "indicator--" + id
    with pytest.raises(ValidationError):
        validate_stix_id("indicator--" + id, "report")
    with pytest.raises(ValidationError):
        validate_stix_id("indicator--bad-id", "indicator")


@pytest.mark.django_db
def test_include_embedded_relationships_attributes():
    s = ProfileSerializer(
        data={
            "extractions": ["pattern_domain_name_only"],
            "defang": False,
            "name": "my-name",
        }
    )
    s.is_valid(raise_exception=True)

    with pytest.raises(ValidationError, match="value must end with _ref or _refs"):
        s = ProfileSerializer(
            data={
                "extractions": ["pattern_domain_name_only"],
                "defang": False,
                "name": "my-name",
                "include_embedded_relationships_attributes": ["abcde_ref", "acd"],
            }
        )
        s.is_valid(raise_exception=True)
    s = ProfileSerializer(
        data={
            "extractions": ["pattern_domain_name_only"],
            "defang": False,
            "name": "my-name",
            "include_embedded_relationships_attributes": ["abcde_ref"],
        }
    )
    s.is_valid(raise_exception=True)
