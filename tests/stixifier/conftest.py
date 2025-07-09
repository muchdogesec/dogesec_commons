import uuid
import pytest
from pytest_django.fixtures import skip_if_no_django, SettingsWrapper




@pytest.fixture(autouse=True, scope="package")
def s_settings():
    skip_if_no_django()

    settings = SettingsWrapper()
    settings.STIXIFIER_NAMESPACE = uuid.uuid4()
    settings.GOOGLE_VISION_API_KEY = settings.ARANGODB_DATABASE_VIEW = settings.INPUT_TOKEN_LIMIT = None
    yield settings
    settings.finalize()