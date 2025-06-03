import uuid
from django.test import TransactionTestCase
from django.urls import include, path
import pytest
from rest_framework.test import APIRequestFactory
from rest_framework import status
from rest_framework.response import Response
from unittest.mock import MagicMock, patch
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
from dogesec_commons.stixifier.views import ExtractorsView, ProfileView

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


class ProfileViewTest(TransactionTestCase, URLPatternsTestCase):
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



class ExtractorsViewTest(URLPatternsTestCase):
    router = routers.SimpleRouter()
    router.register("", ExtractorsView, "extractors-view")
    urlpatterns = [
        path("extractors/", include(router.urls)),
    ]

    
    def list_extractor_tester(self, filters):
        response = self.client.get(f"/extractors/", query_params=filters)
        assert response.status_code == 200
        extractors = response.data['extractors']

        if type := filters.get('type'):
            assert {ex['type'] for ex in extractors} == {type}

        if (web_app := filters.get('web_app', None)) != None:
            assert {ex.get('dogesec_web') for ex in extractors} == {web_app}

        if name := filters.get('name'):
            for ex in extractors:
                assert name.lower() in ex.get('name', '').lower()

    def test_list_extractors(self):
        filters = [
            dict(name='ipv4'),
            dict(name='ipv4', web_app=True),
            dict(),
            dict(type='ai'),
            dict(type='pattern'),
            dict(type='lookup'),
        ]
        for filter in filters:
            with self.subTest(f'test_filters: {filter}', filters=filters):
                self.list_extractor_tester(filter)


    def test_retrieve_extractor(self):
        with patch.object(ExtractorsView, 'get_all') as mock_get_all:
            extractor_id = 'mocked_id'
            mocked_extractor = {'name': 'this should be the response'}
            mock_get_all.return_value = {extractor_id: mocked_extractor}
            response = self.client.get(f"/extractors/{extractor_id}/")
            assert response.status_code == 200
            extractors = response.data == mocked_extractor