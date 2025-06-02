import uuid
from django.test import TransactionTestCase
from django.urls import include, path
import pytest
from rest_framework.test import APIRequestFactory
from rest_framework import status
from rest_framework.response import Response
from unittest.mock import patch
from rest_framework.test import APITestCase, URLPatternsTestCase
from rest_framework import routers

from dogesec_commons.objects.views import (
    ObjectsWithReportsView,
    SCOView,
    SDOView,
    SMOView,
    SROView,
    SingleObjectView,
)
from dogesec_commons.stixifier.models import Profile
from dogesec_commons.stixifier.views import ProfileView

factory = APIRequestFactory()


def get_profile_data():
    return {
        "name": "test-profile",
        "extractions": ["pattern_host_name"],
        "extract_text_from_image": False,
        "defang": True,
        "relationship_mode": "standard",
        "ai_settings_relationships": None,
        "ai_settings_extractions": [],
        "ai_content_check_provider": None,
        "ai_summary_provider": None,
        "ai_create_attack_flow": False,
    }


class SingleObjectsViewTest(TransactionTestCase, URLPatternsTestCase):
    router = routers.SimpleRouter()
    router.register("", ProfileView, "profiles-view")
    urlpatterns = [
        path("profiles/", include(router.urls)),
    ]
    stix_id = "stix-object--" + str(uuid.uuid4())

    def test_create_profile(self):
        profile_data = get_profile_data()
        response = self.client.post("/profiles/", profile_data, content_type="application/json")
        assert response.status_code == 201, response.data
        assert "id" in response.data
        for k in [
            "name",
            "extractions",
            "extract_text_from_image",
            "relationship_mode",
            "defang",
        ]:
            assert profile_data[k] == response.data[k]

    def test_list_profiles(self):
        p = Profile.objects.create(**get_profile_data())
        response = self.client.get("/profiles/")
        assert response.status_code == 200
        profiles = response.data['profiles']
        assert isinstance(profiles, list)
        assert str(p.id) == profiles[0]['id']

    
    def test_retrieve_profiles(self):
        p = Profile.objects.create(**get_profile_data())
        response = self.client.get(f"/profiles/{p.id}/")
        assert response.status_code == 200
        profile = response.data
        assert isinstance(profile, dict)
        assert str(p.id) == profile['id']

    
    def test_delete_profiles(self):
        p = Profile.objects.create(**get_profile_data())
        response = self.client.delete(f"/profiles/{p.id}/")
        assert response.status_code == 204

        response = self.client.get(f"/profiles/{p.id}/")
        assert response.status_code == 404, "should already be deleted"