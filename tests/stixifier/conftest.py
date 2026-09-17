import uuid
import pytest
from django.conf import settings
from django.test import override_settings

@pytest.fixture(autouse=True, scope="package")
def s_settings():
    if not settings.configured:
        pytest.skip("Django settings are not configured")

    with override_settings(
        STIXIFIER_NAMESPACE=uuid.uuid4(),
        GOOGLE_VISION_API_KEY=None,
        ARANGODB_DATABASE_VIEW=None,
        INPUT_TOKEN_LIMIT=None,
    ):
        yield settings
