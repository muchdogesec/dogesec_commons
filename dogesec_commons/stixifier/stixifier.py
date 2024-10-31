import io
import json
import logging
from pathlib import Path
import shutil
import uuid
from attr import dataclass

from ..objects import db_view_creator
from . import models
import tempfile
from file2txt.converter import get_parser_class
from txt2stix import txt2stix
from txt2stix.stix import txt2stixBundler
from txt2stix.ai_session import GenericAIExtractor
from stix2arango.stix2arango import Stix2Arango
from django.conf import settings


from file2txt.converter import Fanger, get_parser_class
from file2txt.parsers.core import BaseParser


def all_extractors(names, _all=False):
    retval = {}
    extractors = txt2stix.extractions.parse_extraction_config(txt2stix.INCLUDES_PATH).values()
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





class StixifyProcessor:
    def __init__(self, file: io.FileIO, profile: models.Profile, job_id: uuid.UUID, post=None, file2txt_mode='html', report_id=None, base_url=None) -> None:
        self.job_id = str(job_id)
        self.extra_data = dict()
        self.report_id = report_id
        self.profile = profile
        self.collection_name = "stixify"
        self.tmpdir = Path(tempfile.mkdtemp(prefix='stixify-'))
        self.file2txt_mode = file2txt_mode
        self.md_images = []
        self.processed_image_base_url = ""
        self.base_url = base_url

        self.filename = self.tmpdir/Path(file.name).name
        self.filename.write_bytes(file.read())

        self.task_name = f"{self.profile.name}/{self.job_id}/{self.report_id}"
        
    def setup(self, /, report_prop: ReportProperties, extra={}):
        self.extra_data.update(extra)
        self.report_prop = report_prop

    def file2txt(self):
        parser_class = get_parser_class(self.file2txt_mode, self.filename.name)
        converter: BaseParser = parser_class(self.filename, self.file2txt_mode, self.profile.extract_text_from_image, settings.GOOGLE_VISION_API_KEY, base_url=self.base_url)
        output = converter.convert(processed_image_base_url=self.processed_image_base_url)
        if self.profile.defang:
            output = Fanger(output).defang()
        for name, img in converter.images.items():
            img_file = io.BytesIO()
            img_file.name = name
            img.save(img_file, format='png')
            self.md_images.append(img_file)
            
        self.output_md = output
        self.md_file = self.tmpdir/f"post_md_{self.report_id or 'file'}.md"
        self.md_file.write_text(self.output_md)

    def txt2stix(self):
        extractors = all_extractors(self.profile.extractions)
        extractors_map = {}
        for extractor in extractors.values():
            if extractors_map.get(extractor.type):
                extractors_map[extractor.type][extractor.slug] = extractor
            else:
                extractors_map[extractor.type] = {extractor.slug: extractor}
        aliases = all_extractors(self.profile.aliases)
        whitelists = all_extractors(self.profile.whitelists)

        bundler = txt2stixBundler(
            self.report_prop.name,
            identity=self.report_prop.identity,
            tlp_level=self.report_prop.tlp_level,
            confidence=self.report_prop.confidence,
            labels=self.report_prop.labels,
            description=self.output_md, 
            extractors=extractors,
            report_id=self.report_id,
            created=self.report_prop.created,
        )
        self.extra_data['_stixify_report_id'] = str(bundler.report.id)
        input_text = txt2stix.remove_data_images(self.output_md)
        aliased_input = txt2stix.aliases.transform_all(aliases.values(), input_text)
        bundler.whitelisted_values = txt2stix.lookups.merge_whitelists(whitelists.values())

        ai_extractor_session = GenericAIExtractor.openai()
        all_extracts = txt2stix.extract_all(bundler, extractors_map, aliased_input, ai_extractor=ai_extractor_session)
 
        if self.profile.relationship_mode == models.RelationshipMode.AI and sum(map(lambda x: len(x), all_extracts.values())):
            txt2stix.extract_relationships_with_ai(bundler, aliased_input, all_extracts, ai_extractor_session)

        if ai_extractor_session.initialized:
            (self.tmpdir/f"conversation_{self.report_id}.md").write_text(ai_extractor_session.get_conversation())
        return bundler


    def process(self) -> str:
        logging.info(f"running file2txt on {self.task_name}")
        self.file2txt()
        logging.info(f"running txt2stix on {self.task_name}")
        bundler = self.txt2stix()
        self.write_bundle(bundler)
        logging.info(f"uploading {self.task_name} to arangodb via stix2arango")
        self.upload_to_arango()
        return bundler.report.id

    def write_bundle(self, bundler: txt2stixBundler):
        bundle = json.loads(bundler.to_json())
        for obj in bundle['objects']:
            obj.update(self.extra_data)
        self.bundle = json.dumps(bundle, indent=4)
        self.bundle_file = self.tmpdir/f"bundle_{self.report_id}.json"
        self.bundle_file.write_text(self.bundle)
        

    def upload_to_arango(self):
        s2a = Stix2Arango(
            file=str(self.bundle_file),
            database=settings.ARANGODB_DATABASE,
            collection=self.collection_name,
            stix2arango_note=f"stixify-job--{self.job_id}",
            ignore_embedded_relationships=False,
            host_url=settings.ARANGODB_HOST_URL,
            username=settings.ARANGODB_USERNAME,
            password=settings.ARANGODB_PASSWORD,
        )
        db_view_creator.link_one_collection(s2a.arango.db, settings.VIEW_NAME, f"{self.collection_name}_edge_collection")
        db_view_creator.link_one_collection(s2a.arango.db, settings.VIEW_NAME, f"{self.collection_name}_vertex_collection")
        s2a.run()

    def __del__(self):
        shutil.rmtree(self.tmpdir)