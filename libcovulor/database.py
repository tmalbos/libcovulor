from bson.objectid import ObjectId
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.errors import PyMongoError

import math

class Database:
    def __init__(self, mongodb_server: str = "mongodb://mongodb", port: int = 27017, db_name: str = "plexicus"):
        self.client = MongoClient(mongodb_server, port)
        self.db = self.client[db_name]
        self.client_collection = self.db['Client']
        self.cwes_collection = self.db['CWE']
        self.findings_collection = self.db['Finding']
        self.notifications_collection = self.db['Notification']
        self.owasps_collection = self.db['OWASP']
        self.remediation_collection = self.db['Remediation']
        self.repositories_collection = self.db['Repository']
        self.rules_collection = self.db['Rules']
        self.scans_collection = self.db['Scan']
        self.scan_requests_collection = self.db['ScanRequest']
        self.users_collection = self.db['Users']
        self.invitations_collection = self.db['Invitations']
        self.FIRST_PAGE = 0
        self.ENTRIES_PER_PAGE = 10

    def get_match_query(self, client_id: str, filters: dict = None) -> dict:
        if filters is None:
            filters = {}
        return {'client_id': client_id,
                **filters}

    def delete_one(self, collection: Collection, client_id: str, _id: str):
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
    
    def delete_many(self, collection: Collection, client_id: str, filters: dict = None):
        query_filter = self.get_match_query(client_id, filters)

        try:
            result = collection.delete_many(query_filter)
            return {"deleted_count": result.deleted_count}
        except PyMongoError as e:
            print(f'Error: {e}')
            return None

    def find_many(self, collection: Collection, client_id: str, options: dict = None):
        filters, fields, sort_field, sort_order, paginate, skip, page_size = None, None, "_id", 1, True, self.FIRST_PAGE, self.ENTRIES_PER_PAGE

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
            page_skip = pagination_options.get('page', self.FIRST_PAGE)
            page_size = pagination_options.get('page_size', self.ENTRIES_PER_PAGE) if paginate else self.ENTRIES_PER_PAGE
            skip = max(page_skip * page_size, self.FIRST_PAGE) if paginate else self.FIRST_PAGE

        filters_query = self.get_match_query(client_id, filters)
        total_elements = collection.count_documents(filters_query)
        total_pages = math.ceil(total_elements / page_size) if paginate else 0

        try:
            pagination_meta = {}

            if paginate:
                results = list(collection.find(filters_query, fields).sort([(sort_field, sort_order)]).skip(skip).limit(page_size))
                pagination_meta["pagination"] = {
                    "page": skip // page_size + 1,
                    "pageCount": total_pages,
                    "pageSize": page_size,
                    "total": total_elements
                }
            else:
                results = list(collection.find(filters_query, fields).sort([(sort_field, sort_order)]))

            for result in results:
                result['_id'] = str(result['_id'])

            return {"data": results,
                    "meta": pagination_meta}
        except PyMongoError as e:
            print(f'Error: {e}')

            return None

    def find_one(self, collection: Collection, client_id: str, _id: str):
        try:
            result = collection.find_one({"_id": ObjectId(_id),
                                        "client_id": client_id})

            if result is None:
                return None

            result["_id"] = str(result["_id"])

            return result
        except PyMongoError as e:
            print(f'Error: {e}')

            return None

    def update_one(self, collection: Collection, client_id: str, _id: str, data: dict):
        query_filter = {"_id": ObjectId(_id),
                        "client_id": client_id}

        try:
            result = collection.update_one(query_filter, {"$set": data})
            existing_document = collection.find_one(query_filter)
            existing_document["_id"] = str(existing_document["_id"])

            return existing_document if result.modified_count > 0 else None
        except PyMongoError as e:
            print(f'Error: {e}')

            return False