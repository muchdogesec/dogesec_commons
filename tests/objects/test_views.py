import uuid
from django.urls import include, path
import pytest
from rest_framework.test import APIRequestFactory
from rest_framework import status
from rest_framework.response import Response
from unittest.mock import patch
from rest_framework.test import APITestCase, URLPatternsTestCase
from rest_framework import routers

from dogesec_commons.objects.views import ObjectsWithReportsView, SCOView, SDOView, SMOView, SROView, SingleObjectView

factory = APIRequestFactory()


@pytest.mark.django_db
@patch("dogesec_commons.objects.views.ArangoDBHelper.get_scos")
def test_sco_view_list_success(mock_get_scos):
    mock_get_scos.return_value = Response({"results": ["filtered-sco"]})
    request = factory.get("/api/objects/sco/")
    response = SCOView.as_view({"get": "list"})(request)
    mock_get_scos.assert_called_once()
    assert response == mock_get_scos.return_value


@pytest.mark.django_db
@patch("dogesec_commons.objects.views.ArangoDBHelper.get_scos")
def test_sco_view_list_with_post_id(mock_get_scos):
    mock_get_scos.return_value = Response({"results": ["filtered-sco"]})
    request = factory.get("/api/objects/sco/?post_id=test123")
    response = SCOView.as_view({"get": "list"})(request)
    mock_get_scos.assert_called_once_with(matcher={"_obstracts_post_id": "test123"})
    assert response == mock_get_scos.return_value


@pytest.mark.django_db
@patch("dogesec_commons.objects.views.ArangoDBHelper.get_smos")
def test_smo_view_list_success(mock_get_smos):
    mock_get_smos.return_value = Response({"results": ["mock-smo"]})
    request = factory.get("/api/objects/smo/")
    response = SMOView.as_view({"get": "list"})(request)
    assert response == mock_get_smos.return_value
    mock_get_smos.assert_called_once()


@pytest.mark.django_db
@patch("dogesec_commons.objects.views.ArangoDBHelper.get_sros")
def test_sro_view_list_success(mock_get_sros):
    mock_get_sros.return_value = Response({"results": ["mock-sro"]})
    request = factory.get("/api/objects/sro/")
    response = SROView.as_view({"get": "list"})(request)
    assert response == mock_get_sros.return_value
    mock_get_sros.assert_called_once()


@pytest.mark.django_db
@patch("dogesec_commons.objects.views.ArangoDBHelper.get_sdos")
def test_sdo_view_list(mock_get_sdos):
    mock_get_sdos.return_value = Response({"results": ["filtered-sdo"]})
    request = factory.get("/api/objects/sdo/")
    response = SDOView.as_view({"get": "list"})(request)
    mock_get_sdos.assert_called_once()
    assert response == mock_get_sdos.return_value


class SingleObjectsViewTest(URLPatternsTestCase):
    router = routers.SimpleRouter()
    router.register('', ObjectsWithReportsView, 'object-view')
    urlpatterns = [
        path('objects/', include(router.urls)),
    ]
    stix_id = 'stix-object--'+str(uuid.uuid4())

    @patch("dogesec_commons.objects.views.ArangoDBHelper.get_objects_by_id")
    def test_retrieve(self, mock_get_objects_by_id):
        mock_get_objects_by_id.return_value = Response()
        url = f'/objects/{self.stix_id}/'
        response = self.client.get(url, format='json')
        mock_get_objects_by_id.assert_called_once_with(self.stix_id)
        assert response == mock_get_objects_by_id.return_value

    def test_lookup_value_regex(self):
        url = f'/objects/bad-stix-id/'
        response = self.client.get(url, format='json')
        assert response.status_code == 404, "should fail because of bad stix_id"


    @patch("dogesec_commons.objects.views.ArangoDBHelper.get_object_bundle")
    def test_bundle(self, mock_get_object_bundle):
        mock_get_object_bundle.return_value = Response()
        url = f'/objects/{self.stix_id}/bundle/'
        response = self.client.get(url, format='json')
        mock_get_object_bundle.assert_called_once_with(self.stix_id)
        assert response == mock_get_object_bundle.return_value

    

    @patch("dogesec_commons.objects.views.ArangoDBHelper.get_containing_reports")
    def test_reports(self, mock_get_containing_reports):
        mock_get_containing_reports.return_value = Response()
        url = f'/objects/{self.stix_id}/reports/'
        response = self.client.get(url, format='json')
        mock_get_containing_reports.assert_called_once_with(self.stix_id)
        assert response == mock_get_containing_reports.return_value

    

    @patch("dogesec_commons.objects.views.ArangoDBHelper.delete_report_object")
    def test_destroy_report(self, mock_delete_report_object):
        mock_delete_report_object.return_value = Response()
        report_id = f'report--{uuid.uuid4()}'
        url = f'/objects/{self.stix_id}/reports/{report_id}/'
        response = self.client.delete(url, format='json')
        assert response.status_code != 404
        mock_delete_report_object.assert_called_once_with(report_id=report_id, object_id=self.stix_id)
        assert response == mock_delete_report_object.return_value

    