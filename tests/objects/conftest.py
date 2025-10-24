from django.conf import settings
from arango.client import ArangoClient


def pytest_sessionstart(session):
    client = ArangoClient(hosts=settings.ARANGODB_HOST_URL)
    sys_db = client.db(
        "_system",
        username=settings.ARANGODB_USERNAME,
        password=settings.ARANGODB_PASSWORD,
    )