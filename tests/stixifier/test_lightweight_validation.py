import pytest
from rest_framework.exceptions import ValidationError

from dogesec_commons.stixifier.serializers import validate_model


@pytest.mark.parametrize('model', ['openai', 'openai:gpt-5-nano', 'anthropic:claude-sonnet-4-0', 'gemini:models/example', 'openrouter:openai/example:free', 'deepseek'])
def test_validate_model_does_not_construct_a_provider(model, monkeypatch):
    from txt2stix.ai_extractor import LazyExtractorRegistry

    def unexpected_load(*args):
        raise AssertionError('Profile validation must not initialize an AI provider')

    monkeypatch.setattr(LazyExtractorRegistry, '__getitem__', unexpected_load)
    assert validate_model(model) == model


@pytest.mark.parametrize('model', ['unknown:model', 'openai:', 'openai:  '])
def test_validate_model_rejects_invalid_configuration(model):
    with pytest.raises(ValidationError, match='invalid model'):
        validate_model(model)
