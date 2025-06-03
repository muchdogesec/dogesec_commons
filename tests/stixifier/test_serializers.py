

import uuid
import pytest
from dogesec_commons.stixifier.serializers import validate_model, validate_stix_id
from rest_framework.validators import ValidationError


def test_validate_model():
    assert validate_model('openai') == 'openai'
    assert validate_model('deepseek') == 'deepseek'
    assert validate_model('') == None
    with pytest.raises(ValidationError):
        validate_model('random:10s')


def test_validate_stix_id():
    id = str(uuid.uuid4())
    assert validate_stix_id('report--'+id, 'report') == 'report--'+id
    assert validate_stix_id('indicator--'+id, 'indicator') == 'indicator--'+id
    with pytest.raises(ValidationError):
        validate_stix_id('indicator--'+id, 'report')
    with pytest.raises(ValidationError):
        validate_stix_id('indicator--bad-id', 'indicator')