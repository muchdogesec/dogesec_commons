import itertools
import time
from urllib.parse import urljoin

from dogesec_commons.objects.helpers import ArangoDBHelper
from dogesec_commons.objects.kb_sync.mappings import KNOWLEDGEBASE_TYPE_MAPPING
from dogesec_commons.objects.kb_sync.retriever import STIXObjectRetriever


def batched(iterable, n):
    """Yield lists of size n from iterable."""
    it = iter(iterable)

    while True:
        batch = list(itertools.islice(it, n))

        if not batch:
            return

        yield batch


def get_existing_object_ids(collection_name, knowledgebase_type):
    config = KNOWLEDGEBASE_TYPE_MAPPING[knowledgebase_type]

    helper = ArangoDBHelper(collection_name, None)

    stix_type = config["stix_type"]

    if isinstance(stix_type, str):
        stix_type = [stix_type]

    bind_vars = {
        "@collection": collection_name,
        "stix_type": stix_type,
    }

    filters = ["doc.type IN @stix_type"]

    if config.get("source_name"):
        bind_vars["source_name"] = config["source_name"]

        filters.append("doc.external_references[0].source_name == @source_name")

    if config.get("mitre_domain"):
        bind_vars["mitre_domain"] = config["mitre_domain"]

        filters.append("@mitre_domain IN doc.x_mitre_domains")

    filter_str = " AND ".join(filters)

    query = f"""
    FOR doc IN @@collection
    FILTER {filter_str}
    RETURN DISTINCT doc.id
        """

    stix_ids = helper.execute_query(
        query,
        bind_vars=bind_vars,
        paginate=False,
    )
    return stix_ids


def get_updates_for_ids(
    stix_ids,
    knowledgebase_type,
    update_time,
):

    config = KNOWLEDGEBASE_TYPE_MAPPING[knowledgebase_type]
    retriever = STIXObjectRetriever(config.get("host", "ctibutler"))

    updates = {}

    for chunk in batched(stix_ids, 50):
        chunk_values = ",".join(chunk)

        for obj in retriever.retrieve_objects(
            config["endpoint"].format(values=chunk_values),
            config.get("result_key", "objects"),
        ):
            obj["_kb_update_time"] = update_time
            updates[obj["id"]] = obj

    return updates


def get_knowledgebase_objects(
    collection_name,
    knowledgebase_type,
    update_time):
    stix_ids = get_existing_object_ids(collection_name, knowledgebase_type)
    return get_updates_for_ids(stix_ids, knowledgebase_type, update_time)

def make_updates_on_collection(collection_name, updates):
    helper = ArangoDBHelper(collection_name, None)

    query = """
FOR doc IN @@collection
FILTER doc.id IN KEYS(@updates)
LET old_keep = KEEP(doc, KEYS(doc)[* FILTER STARTS_WITH(CURRENT, '_')])
LET data = MERGE(
    old_keep,
    @updates[doc.id]
)
REPLACE doc._key WITH data IN @@collection
COLLECT WITH COUNT INTO updated_count
RETURN updated_count
    """

    bind_vars = {
        "@collection": collection_name,
        "updates": updates,
    }

    result = helper.execute_query(
        query,
        bind_vars=bind_vars,
        paginate=False,
    )

    return result[0] if result else 0


def run_on_kb_and_collection(
    collection_name,
    knowledgebase_type,
    update_time,
    progress_callback=None,
    processed_count=0,
    updated_count=0,
):
    print(
        f"Processing collection={collection_name} "
        f"knowledgebase_type={knowledgebase_type}"
    )

    updates = get_knowledgebase_objects(
        collection_name=collection_name,
        knowledgebase_type=knowledgebase_type,
        update_time=update_time,
    )

    if not updates:
        return processed_count, updated_count

    print(f"found {len(updates)} unique items to updates")

    for chunk in batched(updates.items(), 100):
        chunk = dict(chunk)

        chunk_updated_count = make_updates_on_collection(
            collection_name=collection_name,
            updates=chunk,
        )

        processed_count += len(chunk)
        updated_count += chunk_updated_count

        if progress_callback:
            progress_callback(
                knowledgebase_type=knowledgebase_type,
                collection_name=collection_name,
                processed_count=processed_count,
                updated_count=updated_count,
                chunk_size=len(chunk),
            )

    return processed_count, updated_count


def run_on_collections(
    vertex_collection_names,
    knowledgebase_types=None,
    progress_callback=None,
):
    """
    Args:
        vertex_collection_names: iterable[str]
        knowledgebase_types: iterable[str] | None
        progress_callback: callable | None

    progress_callback signature:

        callback(
            *,
            knowledgebase_type: str,
            collection_name: str,
            processed_count: int,
            updated_count: int,
            chunk_size: int,
        )
    """

    update_time = time.time()

    if knowledgebase_types is None:
        knowledgebase_types = list(KNOWLEDGEBASE_TYPE_MAPPING)

    invalid_types = set(knowledgebase_types).difference(KNOWLEDGEBASE_TYPE_MAPPING)

    if invalid_types:
        raise ValueError(f"Unknown knowledgebase types: {sorted(invalid_types)}")

    processed_count = 0
    updated_count = 0

    for knowledgebase_type in knowledgebase_types:
        print(f"Processing knowledgebase_type={knowledgebase_type}")

        for collection_name in vertex_collection_names:
            processed_count, updated_count = run_on_kb_and_collection(
                collection_name=collection_name,
                knowledgebase_type=knowledgebase_type,
                update_time=update_time,
                progress_callback=progress_callback,
                processed_count=processed_count,
                updated_count=updated_count,
            )

    return processed_count, updated_count
