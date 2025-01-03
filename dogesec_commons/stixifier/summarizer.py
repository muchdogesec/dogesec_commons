from typing import Type
from llama_index.core import PromptTemplate
from txt2stix.ai_extractor import ALL_AI_EXTRACTORS, BaseAIExtractor
from llama_index.core.response_synthesizers import SimpleSummarize
from rest_framework.validators import ValidationError

prompt = PromptTemplate("""
<persona>

You are a cyber-security threat intelligence analyst responsible for analysing intelligence. You have a deep understanding of cybersecurity concepts and threat intelligence. You are responsible for simplifying long intelligence reports into concise summaries for other to quickly understand the contents.

</persona>

<requirement>

Using the MARKDOWN of the report provided in <document>, provide an executive summary of it containing no more than one paragraphs.

IMPORTANT: the output should be structured as markdown text.
IMPORTANT: do not put output in code block

</requirement>

<accuracy>

Think about your answer first before you respond.

</accuracy>
                        
<document>
{context_str}
</document>

""")

def get_provider(klass: Type[BaseAIExtractor]):
    class SummarizerSession(klass, provider="~"+klass.provider, register=False):
        system_prompt = """
            You are a cyber-security threat intelligence analyst responsible for analysing intelligence.
            You have a deep understanding of cybersecurity concepts and threat intelligence.
            You are responsible for simplifying long intelligence reports into concise summaries for other to quickly understand the contents.
        """
        def summarize(self, text):
            summarizer = SimpleSummarize(llm=self.llm, text_qa_template=prompt)
            return summarizer.get_response('', text_chunks=[text])
    SummarizerSession.__name__ = klass.__name__.replace('Extractor', 'Summarizer')
    return SummarizerSession


def parse_summarizer_model(value: str):
    try:
        splits = value.split(':', 1)
        provider = splits[0]
        if provider not in ALL_AI_EXTRACTORS:
            raise ValidationError(f"invalid summary provider in `{value}`, must be one of [{list(ALL_AI_EXTRACTORS)}]")
        provider = get_provider(ALL_AI_EXTRACTORS[provider])
        if len(splits) == 2:
            return provider(model=splits[1])
        return provider()
    except ValidationError:
        raise
    except BaseException as e:
        raise ValidationError(f'invalid model: {value}') from e