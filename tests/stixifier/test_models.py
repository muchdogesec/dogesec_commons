import uuid
import pytest
from django.core.exceptions import ValidationError
from dogesec_commons.stixifier import models
from pytest_django.fixtures import skip_if_no_django, SettingsWrapper
from unittest import mock





@pytest.mark.django_db
class TestProfileModel:

    def test_profile_creation_generates_uuid(self):
        profile = models.Profile.objects.create(
            name="Test Profile",
            extractions=["some.extractor"],
            defang=True,
            ai_settings_relationships="default",
            ai_settings_extractions=["ex1"],
            ai_content_check_provider="provider",
            ai_summary_provider="summary_provider",
        )
        assert isinstance(profile.id, uuid.UUID)
        assert profile.name == "Test Profile"
        assert profile.defang is True

    @pytest.mark.parametrize("identity_id", ["identity--xyz", None])
    def test_profile_id_deterministic_with_identity_id(self, identity_id):
        profile1 = models.Profile(
            name="profile-name",
            identity_id=identity_id,
            extractions=["a"],
            defang=True,
            ai_settings_relationships="r",
            ai_settings_extractions=[],
            ai_content_check_provider="p",
            ai_summary_provider="s",
        )
        profile1.save()
        profile_1_id = profile1.id
        profile1.delete()
        profile2 = models.Profile(
            name="profile-name",
            identity_id=identity_id,
            extractions=["a"],
            defang=True,
            ai_settings_relationships="r",
            ai_settings_extractions=[],
            ai_content_check_provider="p",
            ai_summary_provider="s",
        )
        profile2.save()
        assert profile_1_id == profile2.id

    def test_relationship_mode_choices(self):
        assert models.RelationshipMode.AI == "ai"
        assert models.RelationshipMode.STANDARD == "standard"


def test_validate_extractor_valid():
    assert models.validate_extractor(["pattern"], "pattern_host_name") is True


def test_validate_extractor_invalid():
    with pytest.raises(ValidationError):
        models.validate_extractor(["pattern"], "missing_extractor")
