import io
import json
import logging
import os
from pathlib import Path
import shutil
import uuid
from attr import dataclass

from ..objects import db_view_creator
from . import models
import tempfile
from file2txt.converter import get_parser_class
from txt2stix import get_include_path
from txt2stix.stix import txt2stixBundler
from txt2stix.ai_extractor import BaseAIExtractor
from stix2arango.stix2arango import Stix2Arango
from django.conf import settings
from txt2stix.ai_extractor.utils import DescribesIncident


from file2txt.converter import Fanger, get_parser_class
from file2txt.parsers.core import BaseParser
import txt2stix.utils
import txt2stix.txt2stix
import txt2stix.extractions


def all_extractors(names, _all=False):
    retval = {}
    extractors = txt2stix.extractions.parse_extraction_config(
        get_include_path()
    ).values()
    for extractor in extractors:
        if _all or extractor.slug in names:
            retval[extractor.slug] = extractor
    return retval


@dataclass
class ReportProperties:
    name: str = None
    identity: dict = None
    tlp_level: str = None
    confidence: int = None
    labels: list[str] = None
    created: str = None
    kwargs: dict = {}


class StixifyProcessor:
    def __init__(
        self,
        file: io.FileIO,
        profile: models.Profile,
        job_id: uuid.UUID,
        post=None,
        file2txt_mode="html",
        report_id=None,
        base_url=None,
        **kwargs,
    ) -> None:
        self.job_id = str(job_id)
        self.extra_data = dict()
        self.report_id = report_id
        self.profile = profile
        self.collection_name = "stixify"
        self.tmpdir = Path(tempfile.mkdtemp(prefix="stixify-"))
        self.file2txt_mode = file2txt_mode
        self.md_images = []
        self.processed_image_base_url = ""
        self.base_url = base_url
        self.incident: DescribesIncident = None
        self.summary = None

        self.filename = self.tmpdir / Path(file.name).name
        self.filename.write_bytes(file.read())

        self.task_name = f"{self.profile.name}/{job_id}/{self.report_id}"

    def setup(self, /, report_prop: ReportProperties, extra={}):
        self.extra_data.update(extra)
        self.report_prop = report_prop

    def file2txt(self):
        parser_class = get_parser_class(self.file2txt_mode, self.filename.name)
        converter: BaseParser = parser_class(
            self.filename,
            self.file2txt_mode,
            self.profile.extract_text_from_image,
            settings.GOOGLE_VISION_API_KEY,
            base_url=self.base_url,
        )
        output = converter.convert(
            processed_image_base_url=self.processed_image_base_url
        )
        if self.profile.defang:
            output = Fanger(output).defang()
        for name, img in converter.images.items():
            img_file = io.BytesIO()
            img_file.name = name
            img.save(img_file, format="png")
            self.md_images.append(img_file)

        self.output_md = output
        self.md_file = self.tmpdir / f"post_md_{self.report_id or 'file'}.md"
        self.md_file.write_text(self.output_md)

    def txt2stix(self):
        extractors = all_extractors(self.profile.extractions)
        extractors_map = {}
        for extractor in extractors.values():
            if extractors_map.get(extractor.type):
                extractors_map[extractor.type][extractor.slug] = extractor
            else:
                extractors_map[extractor.type] = {extractor.slug: extractor}

        self.bundler = txt2stixBundler(
            self.report_prop.name,
            identity=self.report_prop.identity,
            tlp_level=self.report_prop.tlp_level,
            confidence=self.report_prop.confidence,
            labels=self.report_prop.labels,
            description=self.output_md,
            extractors=extractors,
            report_id=self.report_id,
            created=self.report_prop.created,
            **self.report_prop.kwargs,
        )
        self.extra_data["_stixify_report_id"] = str(self.bundler.report.id)
        input_text = txt2stix.utils.remove_links(
            self.output_md,
            self.profile.ignore_image_refs,
            self.profile.ignore_link_refs,
        )
        ai_extractors = [
            txt2stix.txt2stix.parse_model(model_str)
            for model_str in self.profile.ai_settings_extractions
        ]
        self.txt2stix_data = txt2stix.txt2stix.run_txt2stix(
            self.bundler,
            input_text,
            extractors_map,
            ai_content_check_provider=self.profile.ai_content_check_provider
            and txt2stix.txt2stix.parse_model(self.profile.ai_content_check_provider),
            ai_create_attack_flow=self.profile.ai_create_attack_flow,
            ai_create_attack_navigator_layer=self.profile.ai_create_attack_navigator_layer,
            input_token_limit=settings.INPUT_TOKEN_LIMIT,
            ai_settings_extractions=ai_extractors,
            ai_settings_relationships=self.profile.ai_settings_relationships
            and txt2stix.txt2stix.parse_model(self.profile.ai_settings_relationships),
            relationship_mode=self.profile.relationship_mode,
            ignore_extraction_boundary=self.profile.ignore_extraction_boundary,
            ai_extract_if_no_incidence=self.profile.ai_extract_if_no_incidence,
        )
        self.incident = self.txt2stix_data.content_check
        self.summary = self.incident and self.incident.summary
        return self.bundler

    def process(self) -> str:
        logging.info(f"running file2txt on {self.task_name}")
        self.file2txt()
        logging.info(f"running txt2stix on {self.task_name}")
        bundler: txt2stixBundler = self.txt2stix()
        self.write_bundle(bundler)
        logging.info(f"uploading {self.task_name} to arangodb via stix2arango")
        self.upload_to_arango()
        return bundler.report.id

    def write_bundle(self, bundler: txt2stixBundler):
        bundle = json.loads(bundler.to_json())
        self.bundle = json.dumps(bundle, indent=4)
        self.bundle_file = self.tmpdir / f"bundle_{self.report_id}.json"
        self.bundle_file.write_text(self.bundle)

    def upload_to_arango(self):
        s2a = Stix2Arango(
            file=str(self.bundle_file),
            database=settings.ARANGODB_DATABASE,
            collection=self.collection_name,
            stix2arango_note=f"stixifier-report--{self.report_id}",
            ignore_embedded_relationships=self.profile.ignore_embedded_relationships,
            ignore_embedded_relationships_smo=self.profile.ignore_embedded_relationships_smo,
            ignore_embedded_relationships_sro=self.profile.ignore_embedded_relationships_sro,
            host_url=settings.ARANGODB_HOST_URL,
            username=settings.ARANGODB_USERNAME,
            password=settings.ARANGODB_PASSWORD,
        )
        s2a.arangodb_extra_data.update(self.extra_data)
        db_view_creator.link_one_collection(
            s2a.arango.db,
            settings.ARANGODB_DATABASE_VIEW,
            f"{self.collection_name}_edge_collection",
        )
        db_view_creator.link_one_collection(
            s2a.arango.db,
            settings.ARANGODB_DATABASE_VIEW,
            f"{self.collection_name}_vertex_collection",
        )
        s2a.run()

    def __del__(self):
        shutil.rmtree(self.tmpdir)
