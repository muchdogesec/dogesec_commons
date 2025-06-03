

from unittest.mock import patch
import uuid
import pytest
from dogesec_commons.stixifier.serializers import validate_model, validate_stix_id
from rest_framework.validators import ValidationError
from llama_index.core.response_synthesizers import SimpleSummarize

from dogesec_commons.stixifier.summarizer import parse_summarizer_model

def test_parse_summarizer_model():
    assert parse_summarizer_model('openai:gpt-4o') != None
    assert parse_summarizer_model('deepseek') != None
    with pytest.raises(ValidationError):
        parse_summarizer_model('bad model')

def test_summarize():
    input_to_summarize = 'input_to_summarize'
    provider = parse_summarizer_model('openai:gpt-4o')
    with patch.object(SimpleSummarize, 'get_response') as mock_gfet_response:
        mock_gfet_response.return_value = 'output/summary'
        summary = provider.summarize(input_to_summarize)
        mock_gfet_response.assert_called_once_with('', text_chunks=[input_to_summarize])
        assert summary == mock_gfet_response.return_value
