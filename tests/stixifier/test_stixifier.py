import io
import uuid
import pytest
import json
from pathlib import Path
from tempfile import NamedTemporaryFile
from unittest.mock import patch, MagicMock

from txt2stix import txt2stixBundler

from dogesec_commons.stixifier.stixifier import (
    StixifyProcessor,
    ReportProperties,
)


@pytest.fixture
def fake_file():
    tmp_file = NamedTemporaryFile(delete=False, suffix=".html")
    tmp_file.write(b"<html>Example content</html>")
    tmp_file.seek(0)
    tmp_file.name = "example.html"
    return tmp_file


@pytest.fixture
def fake_profile():
    class FakeProfile:
        name = "test-profile"
        extract_text_from_image = False
        defang = False
        ignore_image_refs = False
        ignore_link_refs = False
        extractions = []
        ai_content_check_provider = None
        ai_create_attack_flow = False
        ai_settings_extractions = []
        ai_settings_relationships = None
        relationship_mode = None
        ignore_extraction_boundary = False
        ai_summary_provider = None
        ignore_embedded_relationships = False
        ignore_embedded_relationships_smo = False
        ignore_embedded_relationships_sro = False

    return FakeProfile()


def test_init(fake_file, fake_profile):
    processor = StixifyProcessor(fake_file, fake_profile, uuid.uuid4())
    assert processor.filename.exists()
    assert processor.tmpdir.exists()
    assert processor.profile == fake_profile


def test_file2txt(fake_file, fake_profile):
    processor = StixifyProcessor(fake_file, fake_profile, uuid.uuid4())

    with patch(
        "dogesec_commons.stixifier.stixifier.get_parser_class"
    ) as mock_get_parser:
        mock_converter = MagicMock()
        mock_converter.convert.return_value = "converted text"
        mock_converter.images = {}
        mock_get_parser.return_value.return_value = mock_converter

        processor.file2txt()
        assert processor.output_md == "converted text"
        assert processor.md_file.exists()


def test_setup(fake_file, fake_profile):
    original_extra = dict(extra_1=1)
    processor = StixifyProcessor(fake_file, fake_profile, uuid.uuid4())
    processor.extra_data = original_extra
    setup_extra = dict(setup_extra=2)
    report_prop = ReportProperties(name="Test Report")
    processor.setup(report_prop, setup_extra)
    assert report_prop == processor.report_prop
    assert processor.extra_data == {
        **original_extra,
        **setup_extra,
    }, "setup should update extra_data"


def test_txt2stix(fake_file, fake_profile, settings):
    fake_profile.extractions = ["test-extractor"]
    fake_profile.ai_settings_extractions = ["some-ai-model"]
    fake_profile.ai_content_check_provider = None
    fake_profile.ai_create_attack_flow = True
    fake_profile.ignore_image_refs = True
    fake_profile.ignore_link_refs = True
    fake_profile.ignore_extraction_boundary = True
    fake_profile.ai_settings_relationships = "relationship-model"
    fake_profile.relationship_mode = "full"

    processor = StixifyProcessor(fake_file, fake_profile, uuid.uuid4())
    processor.output_md = "This is a markdown"
    processor.report_id = "fake-id"

    report_props = ReportProperties(
        name="Test Report",
        identity={"type": "identity", "name": "Org"},
        tlp_level="green",
        confidence=85,
        labels=["test"],
        created="2024-01-01T00:00:00Z",
    )
    processor.setup(report_props)

    with (
        patch(
            "dogesec_commons.stixifier.stixifier.all_extractors", return_value={}
        ) as mock_extractors,
        patch(
            "dogesec_commons.stixifier.stixifier.txt2stixBundler"
        ) as mock_bundler_cls,
        patch(
            "dogesec_commons.stixifier.stixifier.txt2stix.txt2stix.run_txt2stix"
        ) as mock_run,
        patch(
            "dogesec_commons.stixifier.stixifier.txt2stix.utils.remove_links",
            return_value="cleaned text",
        ),
        patch(
            "dogesec_commons.stixifier.stixifier.txt2stix.txt2stix.parse_model",
            side_effect=lambda x: f"parsed({x})",
        ) as mock_parse_model,
    ):
        mock_bundler = MagicMock()
        mock_bundler.report.id = "report--abc"
        mock_bundler_cls.return_value = mock_bundler
        mock_run.return_value.content_check = MagicMock()

        result = processor.txt2stix()

        assert result == mock_bundler

        # Validate bundler was instantiated with expected arguments
        mock_bundler_cls.assert_called_once_with(
            "Test Report",
            identity={"type": "identity", "name": "Org"},
            tlp_level="green",
            confidence=85,
            labels=["test"],
            description="This is a markdown",
            extractors={},
            report_id="fake-id",
            created="2024-01-01T00:00:00Z",
        )

        # Validate remove_links was called with correct arguments
        txt = processor.output_md
        assert txt == "This is a markdown"
        mock_parse_model.assert_any_call("some-ai-model")
        mock_parse_model.assert_any_call("relationship-model")

        # Validate run_txt2stix was called correctly
        mock_run.assert_called_once_with(
            mock_bundler,
            "cleaned text",
            {},
            ai_content_check_provider=None,
            ai_create_attack_flow=True,
            input_token_limit=settings.INPUT_TOKEN_LIMIT,
            ai_settings_extractions=["parsed(some-ai-model)"],
            ai_settings_relationships="parsed(relationship-model)",
            relationship_mode="full",
            ignore_extraction_boundary=True,
            always_extract=False,
        )

        assert processor.txt2stix_data == mock_run.return_value
        assert processor.incident == mock_run.return_value.content_check


def test_summarize_success(fake_file, fake_profile):
    fake_profile.ai_summary_provider = "test-model"
    processor = StixifyProcessor(fake_file, fake_profile, uuid.uuid4())
    processor.output_md = "Some markdown"
    processor.report_id = "1234"
    mock_bundler = MagicMock()
    mock_bundler.report.id = "report--abc"
    mock_bundler.report.created = "2023-01-01T00:00:00Z"
    mock_bundler.report.modified = "2023-01-01T00:00:00Z"
    mock_bundler.report.created_by_ref = "identity--xyz"
    mock_bundler.report.object_marking_refs = []
    mock_bundler.report.labels = []
    mock_bundler.report.confidence = 90
    mock_bundler.report.name = "Dummy Random Report Name"
    processor.bundler = mock_bundler

    with patch(
        "dogesec_commons.stixifier.stixifier.parse_summarizer_model"
    ) as mock_parser:
        mock_summary = MagicMock()
        mock_summary.summarize.return_value = "summary"
        mock_parser.return_value = mock_summary
        summary = processor.summarize()
        assert summary == "summary"
        assert mock_bundler.add_ref.call_count == 2
        objects_added = [c[0][0] for c in mock_bundler.add_ref.call_args_list]
        note_obj = objects_added[0]
        assert note_obj["type"] == "note"
        assert note_obj["id"] == "note--abc"
        for k in ['created', 'modified', 'created_by_ref', 'object_marking_refs', 'labels', 'confidence']:
            assert note_obj[k] == getattr(mock_bundler.report, k)
        assert note_obj['content'] == summary
        assert note_obj['abstract'] == "AI Summary: Dummy Random Report Name"
        assert objects_added[1] == mock_bundler.new_relationship.return_value
        mock_bundler.new_relationship.assert_called_once_with(
            note_obj["id"],
            mock_bundler.report.id,
            relationship_type="summary-of",
            description=f"AI generated summary for {mock_bundler.report.name}",
            external_references=note_obj["external_references"],
        )


def test_write_bundle(fake_file, fake_profile):
    processor = StixifyProcessor(fake_file, fake_profile, uuid.uuid4(), report_id="abc")
    mock_bundler = MagicMock()
    mock_bundler.to_json.return_value = json.dumps({"type": "bundle", "id": "example"})
    processor.write_bundle(mock_bundler)
    assert processor.bundle_file.exists()


def test_upload_to_arango(fake_file, fake_profile):
    processor = StixifyProcessor(fake_file, fake_profile, uuid.uuid4(), report_id="abc")
    processor.bundle_file = Path(processor.tmpdir / "bundle_abc.json")
    processor.bundle_file.write_text("{}")

    with (
        patch("dogesec_commons.stixifier.stixifier.Stix2Arango") as mock_s2a,
        patch(
            "dogesec_commons.stixifier.stixifier.db_view_creator.link_one_collection"
        ) as mock_link,
    ):
        mock_instance = mock_s2a.return_value
        processor.upload_to_arango()
        mock_instance.run.assert_called()
        assert mock_link.call_count == 2


def test_process(fake_file, fake_profile):
    processor = StixifyProcessor(fake_file, fake_profile, uuid.uuid4(), report_id="abc")
    with (
        patch.object(StixifyProcessor, "file2txt") as mock_f2t,
        patch.object(StixifyProcessor, "txt2stix") as mock_t2s,
        patch.object(StixifyProcessor, "summarize") as mock_summarize,
        patch.object(StixifyProcessor, "write_bundle"),
        patch.object(StixifyProcessor, "upload_to_arango") as mock_upload_to_arango,
    ):
        assert processor.process() == mock_t2s.return_value.report.id
        mock_f2t.assert_called_once()
        mock_t2s.assert_called_once()
        mock_summarize.assert_called_once()
        mock_upload_to_arango.assert_called_once()


def test_write_bundle(fake_file, fake_profile):
    processor = StixifyProcessor(fake_file, fake_profile, uuid.uuid4(), report_id="abc")
    bundler = MagicMock()
    bundle_dict = {"some-data": [], "other-data": "2"}
    bundler.to_json.return_value = json.dumps(bundle_dict)
    processor.write_bundle(bundler)
    assert processor.bundle_file.exists()
    assert json.loads(processor.bundle_file.read_text()) == bundle_dict
