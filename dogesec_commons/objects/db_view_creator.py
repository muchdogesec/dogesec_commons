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

FILTER_FIELDS_VERTEX = [
    "type",
    "name",
    "labels",
    "_stix2arango_note",
]
FILTER_FIELDS_EDGE = [
    "source_ref",
    "target_ref",
    "relationship_type",
    "_stix2arango_note",
]
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


def create_view(db: StandardDatabase, view_name):
    logging.info(f"creating view {view_name} in {db.name}")
    primary_sort = []
    for field in SORT_FIELDS:
        primary_sort.append(dict(field=field, direction="asc"))
        primary_sort.append(dict(field=field, direction="desc"))

    try:
        return db.create_arangosearch_view(
            view_name, {"primarySort": primary_sort, "storedValues": [FILTER_FIELDS]}
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
    view = db.view(view_name)
    link = get_link_properties(collection_name)
    if link and collection_name:
        view["links"][collection_name] = link
    logging.info(f"linking collection {collection_name} to {view_name}")
    db.update_arangosearch_view(view_name, view)
    logging.info(f"linked collection {collection_name} to {view_name}")


def link_all_collections(db: StandardDatabase, view: dict):
    links = view.get("links", {})
    view_name = view["name"]
    for collection in db.collections():
        collection_name = collection["name"]
        if collection["system"]:
            continue
        links[collection_name] = get_link_properties(collection_name)
        if not links[collection_name]:
            del links[collection]
            continue
        logging.info(f"linking collection {collection_name} to {view_name}")
    db.update_arangosearch_view(view["name"], view)
    logging.info(f"linked {len(links)} collections to view")


def startup_func():
    logging.info("setting up obstracts database")
    client = ArangoClient(settings.ARANGODB_HOST_URL)
    sys_db = client.db(username=settings.ARANGODB_USERNAME, password=settings.ARANGODB_PASSWORD)
    db = create_database(client, sys_db, conf.DB_NAME)
    view = create_view(db, conf.VIEW_NAME)
    link_all_collections(db, view)
    logging.info("app ready")