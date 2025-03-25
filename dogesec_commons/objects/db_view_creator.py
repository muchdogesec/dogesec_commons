import logging

import arango
import arango.exceptions
from arango.database import StandardDatabase
from arango import ArangoClient

from dogesec_commons.objects import conf

logging.basicConfig(
    level=logging.INFO,
    format='[ARANGODB VIEW] %(levelname)s %(asctime)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

from django.conf import settings


SORT_FIELDS = [
    "id",
    "type",
    "created",
    "modified",
    "name",
]

FILTER_HIDDEN_FIELDS = [
    "_stix2arango_note",
    "_id",
    "_from",
    "_to",
    "_is_ref",
    "_arango_cti_processor_note",
    "_arango_cve_processor_note",
]

FILTER_FIELDS_VERTEX = [
    "type",
    "name",
    "labels",
]
FILTER_FIELDS_EDGE = [
    "source_ref",
    "target_ref",
    "relationship_type",
]
FILTER_SCO_FIELDS = ['value', 'path', 'subject', 'number', 'pid', 'string', 'key', 'iban_number', 'payload_bin', 'hash', 'display_name', 'protocols', 'name', 'body']
FILTER_FIELDS = list(set(FILTER_FIELDS_EDGE + FILTER_FIELDS_VERTEX))


def create_database(client: ArangoClient, sys_db: StandardDatabase, db_name):
    logging.info(f"creating database {db_name}")
    try:
        sys_db.create_database(db_name)
    except arango.exceptions.DatabaseCreateError as e:
        logging.error(e)
    return client.db(
        name=db_name, username=settings.ARANGODB_USERNAME, password=settings.ARANGODB_PASSWORD, verify=True
    )


def create_view(db: StandardDatabase, view_name, sort_fields=SORT_FIELDS, filter_fields=[SORT_FIELDS, FILTER_FIELDS_VERTEX, FILTER_FIELDS_EDGE, FILTER_HIDDEN_FIELDS, FILTER_SCO_FIELDS]):
    logging.info(f"creating view {view_name} in {db.name}")
    primary_sort = []
    for field in sort_fields:
        primary_sort.append(dict(field=field, direction="asc"))
        primary_sort.append(dict(field=field, direction="desc"))

    all_fields = [*filter_fields, sort_fields]

    try:
        logging.info("try updating view (%s) if exists", view_name)
        return update_view(db, all_fields, view_name)
    except BaseException as e:
        logging.info(f"view update not possible: {e}")

    try:
        logging.info("create new view: %s", view_name)
        return db.create_arangosearch_view(
            view_name, {"primarySort": primary_sort, "storedValues": all_fields}
        )
    except arango.exceptions.ViewCreateError as e:
        logging.error(e)
    return db.view(view_name)


def get_link_properties(collection_name: str):
    if collection_name.endswith("_vertex_collection"):
        return {
            "fields": {name: {} for name in FILTER_FIELDS_VERTEX},
        }
    elif collection_name.endswith("_edge_collection"):
        return {
            "fields": {name: {} for name in FILTER_FIELDS_EDGE},
        }
    else:
        return None


def link_one_collection(db: StandardDatabase, view_name, collection_name):
    logging.info(f"linking collection {collection_name} to {view_name}")
    view = db.view(view_name)
    link = {"includeAllFields": True}
    if link and collection_name:
        view["links"][collection_name] = link
    db.update_arangosearch_view(view_name, view)
    logging.info(f"linked collection {collection_name} to {view_name}")


def update_view(db: StandardDatabase, filter_fields, view_name) -> bool:
    view = db.view(view_name)
    view_fields = [sv['fields'] for sv in view['stored_values']]
    def hash_fields(fields: list[list[str]]) -> set[str]:
        hashes = set()
        for ff in fields:
            hash_val = 0
            for f in set(ff):
                hash_val += hash(f)
            hashes.add(hash_val)
        return hashes
    view_hash = hash_fields(view_fields)
    fields_hash = hash_fields(filter_fields)
    
    if view_hash == fields_hash:
        return view
    
    logging.info("old hash does not match new hash, updating...")

    view['storedValues'] = [{"fields": v} for v in filter_fields]
    view["stored_values"] = filter_fields

    new_view = db.update_arangosearch_view(view_name, view)

    # should update but for some reason update not working, so recreate instead
    new_view_hash = hash_fields([sv['fields'] for sv in new_view['stored_values']])
    if new_view_hash != fields_hash:
        db.delete_view(view_name, ignore_missing=True)
        raise Exception("recreate because update is impossible")
    return new_view

def link_all_collections(db: StandardDatabase, view: dict):
    links = view.get("links", {})
    view_name = view["name"]
    for collection in db.collections():
        collection_name = collection["name"]
        if collection["system"]:
            continue
        links[collection_name] = {"includeAllFields": True}
        if not links[collection_name]:
            del links[collection]
            continue
        logging.info(f"linking collection {collection_name} to {view_name}")
    db.update_arangosearch_view(view_name, view)
    logging.info(f"linked {len(links)} collections to view")


def startup_func():
    logging.info("setting up database")
    client = ArangoClient(settings.ARANGODB_HOST_URL)
    sys_db = client.db(username=settings.ARANGODB_USERNAME, password=settings.ARANGODB_PASSWORD)
    db = create_database(client, sys_db, conf.DB_NAME)
    view = create_view(db, conf.ARANGODB_DATABASE_VIEW)
    link_all_collections(db, view)
    logging.info("app ready")