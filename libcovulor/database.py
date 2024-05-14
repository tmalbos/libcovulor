from bson.objectid import ObjectId
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.errors import PyMongoError

import math

# Mongo setup
client = MongoClient("mongodb://mongodb:27017")
db = client["plexicus"]

# Collections
client_collection = db['Client']
cwes_collection = db['CWE']
findings_collection = db['Finding']
notifications_collection = db['Notification']
owasps_collection = db['OWASP']
remediation_collection = db['Remediation']
repositories_collection = db['Repository']
rules_collection = db['Rules']
users_collection = db['Users']
invitations_collection = db['Invitations']

FIRST_PAGE = 0
ENTRIES_PER_PAGE = 10

def get_match_query(client_id: str, filters: dict = None) -> dict:
    return {'client_id': client_id,
            **filters}

def delete_one(collection: Collection, client_id: str, _id: str):
    query_filter = {"_id": ObjectId(_id),
                    "client_id": client_id}

    try:
        existing_document = collection.find_one(query_filter)

        if not existing_document:
            return None

        result = collection.delete_one(query_filter)
        existing_document["_id"] = str(existing_document["_id"])

        return existing_document if result.deleted_count > 0 else None
    except PyMongoError as e:
        print(f'Error: {e}')

        return None

def find_many(collection: Collection, client_id: str, options: dict = None):
    filters, fields, sort_field, sort_order, paginate, skip, page_size = None, None, None, None, True, FIRST_PAGE, ENTRIES_PER_PAGE

    if options:
        # Filters & Fields
        filters = options.get('filters', None)
        fields = options.get('fields', None)

        # Sorting
        sort_options = options.get('sort', {})
        sort_field = sort_options.get('field', '_id')
        sort_order = sort_options.get('order', 1)

        # Pagination
        pagination_options = options.get('pagination', {})
        paginate = pagination_options.get('paginate', True)
        page_skip = pagination_options.get('page', FIRST_PAGE)
        page_size = pagination_options.get('page_size', ENTRIES_PER_PAGE) if paginate else ENTRIES_PER_PAGE
        skip = max(page_skip * page_size, FIRST_PAGE) if paginate else FIRST_PAGE

    filters_query = get_match_query(client_id, filters)
    total_elements = collection.count_documents(filters_query)
    total_pages = math.ceil(total_elements / page_size) if paginate else 0

    try:
        results = list(collection.find(filters_query, fields).sort(sort_field, sort_order).skip(skip).limit(page_size))
        pagination_meta = {}

        if paginate:
            pagination_meta["pagination"] = {
                "page": skip // page_size + 1,
                "pageCount": total_pages,
                "pageSize": page_size,
                "total": total_elements
            }

        for result in results:
            result['_id'] = str(result['_id'])

        return {"data": results,
                "meta": pagination_meta}
    except PyMongoError as e:
        print(f'Error: {e}')

        return None

def find_one(collection: Collection, client_id: str, _id: str):
    try:
        result = collection.find_one({"client_id": client_id,
                                          "_id": ObjectId(_id)})

        if result is None:
            return None

        result["_id"] = str(result["_id"])

        return result
    except PyMongoError as e:
        print(f'Error: {e}')

        return None

def update_one(collection: Collection, client_id: str, _id: str, data: dict):
    query_filter = {"client_id": client_id,
                    "_id": ObjectId(_id)}

    try:
        result = collection.update_one(query_filter, {"$set": data})
        existing_document = collection.find_one(query_filter)
        existing_document["_id"] = str(existing_document["_id"])

        return existing_document if result.modified_count > 0 else None
    except PyMongoError as e:
        print(f'Error: {e}')

        return False