import time
from django.conf import settings
from django.http import HttpRequest
import rest_framework.request
import pytest
from dogesec_commons.objects.db_view_creator import startup_func
from dogesec_commons.objects.helpers import ArangoDBHelper
from stix2arango.stix2arango import Stix2Arango
import contextlib
from arango.client import ArangoClient

def make_s2a_uploads(collection, objects):
    helper = ArangoDBHelper()
    helper.db.collection(collection).insert_many(objects)
    return helper


def as_arango2stix_db(db_name):
    if db_name.endswith('_database'):
        return '_'.join(db_name.split('_')[:-1])
    return db_name

@contextlib.contextmanager
def make_s2a_uploads(uploads: list[tuple[str, list[dict]]], truncate_collection=False, database=settings.ARANGODB_DATABASE, **kwargs):
    database = as_arango2stix_db(database)

    for collection, objects in uploads:
        s2a = Stix2Arango(database=database, collection=collection, file='', host_url=settings.ARANGODB_HOST_URL, **kwargs)
        s2a.run(data=dict(type='bundle', id='', objects=objects))
    
    startup_func()
    time.sleep(1)
    yield s2a

    if truncate_collection:
        for collection, _ in uploads:
            s2a.arango.db.collection(collection+'_vertex_collection').truncate()
            s2a.arango.db.collection(collection+'_edge_collection').truncate()

@contextlib.contextmanager
def make_uploads(collection_name):
    client = ArangoClient(
        hosts=settings.ARANGODB_HOST_URL
    )
    db = client.db(settings.ARANGODB_DATABASE, username=settings.ARANGODB_USERNAME, password=settings.ARANGODB_PASSWORD)
    transaction_db = db.begin_transaction(write=collection_name, allow_implicit=True)
    try:
        if not transaction_db.has_collection(collection_name):
            transaction_db.create_collection(collection_name)
        yield transaction_db
    except:
        raise
    finally:
        transaction_db.abort_transaction()

def request_from_queries(**queries):
    r = rest_framework.request.Request(HttpRequest())
    r.query_params.update(queries)
    return r