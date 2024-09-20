from bson.objectid import ObjectId
from pymongo import MongoClient
from pymongo.errors import PyMongoError, OperationFailure

import asyncio
import math
import motor.motor_asyncio
import random

class MongoDBClient:
    def __init__(self, database_username=None, database_password=None, database_host="mongodb", port: int = 27017, database_options=None, db_name="plexicus"):
        uri_parts = []

        if database_username and database_password:
            uri_parts.append(f"{database_username}:{database_password}@")
        elif database_username:
            uri_parts.append(f"{database_username}@")

        if database_host:
            uri_parts.append(f"{database_host}")
        
        uri_parts.append(f":{port}")

        if database_options:
            uri_parts.append(f"/?{database_options}")
        
        self.database_uri = "mongodb://" + "".join(uri_parts)
        self.db_name = db_name
        self.client = None
        self.db = None

    def __enter__(self):
        self.client = MongoClient(self.database_uri)
        self.db = self.client[self.db_name]
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.client.close()

    async def __aenter__(self):
        self.client = motor.motor_asyncio.AsyncIOMotorClient(self.database_uri)
        self.db = self.client[self.db_name]
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.client.close()

    def get_collection(self, collection_name):
        return self.db[collection_name]

class Database:
    def __init__(self, database_username=None, database_password=None, database_host="mongodb", port: int = 27017, database_options = None, db_name = "plexicus", retries = 5):
        self.db_username = database_username
        self.db_password = database_password
        self.db_host = database_host
        self.db_port = port
        self.db_options = database_options
        self.db_name = db_name
        self.retries = 5
        self.retry_delay=4
        self.batch_size=50
        self.client_collection = 'Client'
        self.cwes_collection = 'CWE'
        self.findings_collection = 'Finding'
        self.notifications_collection = 'Notification'
        self.owasps_collection = 'OWASP'
        self.remediation_collection = 'Remediation'
        self.repositories_collection = 'Repository'
        self.rules_collection = 'Rules'
        self.sbom_finding_collection = 'SBOMFinding'
        self.scans_collection = 'Scan'
        self.scan_requests_collection = 'ScanRequest'
        self.users_collection = 'Users'
        self.invitations_collection = 'Invitations'
        self.epss_collection = 'EPSS'
        self.FIRST_PAGE = 0
        self.ENTRIES_PER_PAGE = 10

    def get_match_query(self, client_id: str, filters: dict = None) -> dict:
        if filters is None:
            filters = {}
        return {'client_id': client_id,
                **filters}

    async def execute_query(self, collection_name: str, query: callable(any)) -> any:
        amongo = MongoDBClient(self.db_username, self.db_password, self.db_host, self.db_port, self.db_options, self.db_name)

        async with amongo:
            collection = amongo.get_collection(collection_name)

            # for attempt in range(self.retries):
            while True:
                try:
                    return await query(collection)
                except OperationFailure as e:
                    if 'TooManyRequests' in str(e):
                        # wait_time = (2 ** attempt) + random.uniform(0, 1)
                        wait_time = (2 ** random.uniform(0, 1))  # Exponential backoff with jitter
                        await asyncio.sleep(wait_time)
                    else:
                        print(f"Error: {e}")
                        return None
                except PyMongoError as e:
                    print(f'Error: {e}')
                    return None

            # print('Max retries reached')
            
            # return None

    async def aggregate(self, collection_name: str, pipeline: list) -> list:
        async def aggregate_query(collection):
            result = await collection.aggregate(pipeline).to_list(length=None)

            return result if result else []

        aggregate_result = await self.execute_query(collection_name, aggregate_query)

        return aggregate_result if aggregate_result else []

    async def count_documents(self, collection_name: str, filter_query: dict) -> int:
        async def count_documents_query(collection):
            result = await collection.count_documents(filter_query)

            return result if result else 0

        count_documents_result = await self.execute_query(collection_name, count_documents_query)

        return count_documents_result if count_documents_result else 0

    async def delete_many(self, collection_name: str, client_id: str, filters: dict = None):
        query_filter = self.get_match_query(client_id, filters)

        async def delete_many_query(collection):
            total_deleted_count = 0
            ids_to_delete = []
            try:
                async for document in collection.find(query_filter, {'_id': 1}).batch_size(self.batch_size):
                    ids_to_delete.append(document['_id'])
                    
                    if len(ids_to_delete) >= self.batch_size:
                        await try_delete(collection, ids_to_delete)
                        total_deleted_count += len(ids_to_delete)
                        ids_to_delete = []

                if ids_to_delete:  # Delete remaining documents
                    await try_delete(collection, ids_to_delete)
                    total_deleted_count += len(ids_to_delete)

            except Exception as e:
                print(f"Error trying to delete: {e}")

            return {"deleted_count": total_deleted_count}

        async def try_delete(collection, ids_to_delete):
            while True:
                try:
                    result = await collection.delete_many({'_id': {'$in': ids_to_delete}})
                    return result.deleted_count
                except PyMongoError as e:
                    if "Request rate is large" in str(e):
                        await asyncio.sleep(self.retry_delay)
                        continue
                    else:
                        print(f"Unknown error: {e}")
                        raise

        delete_many_result = await self.execute_query(collection_name, delete_many_query)

        return delete_many_result if delete_many_result else {'deleted_count': 0}

    async def delete_one(self, collection_name: str, client_id: str, _id: str):
        async def delete_one_query(collection):
            result = await collection.delete_one({"_id": ObjectId(_id), "client_id": client_id})

            return result.deleted_count > 0 if result else False

        delete_one_result = await self.execute_query(collection_name, delete_one_query)

        return delete_one_result if delete_one_result else False

    async def find_many(self, collection_name: str, client_id: str, options: dict = None):
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

        async def find_many_query(collection):
            total_elements = await collection.count_documents(filters_query)
            total_pages = math.ceil(total_elements / page_size) if paginate else 0
            pagination_meta = {}
            
            results = []
            if paginate:
                cursor = collection.find(filters_query, fields).sort([(sort_field, sort_order)]).skip(skip).batch_size(self.batch_size)
                async for document in cursor.limit(page_size):
                    document['_id'] = str(document['_id'])
                    results.append(document)
                pagination_meta["pagination"] = {
                    "page": skip // page_size + 1,
                    "pageCount": total_pages,
                    "pageSize": page_size,
                    "total": total_elements
                }
            else:
                cursor = collection.find(filters_query, fields).sort([(sort_field, sort_order)]).batch_size(self.batch_size)
                async for document in cursor.limit(page_size):
                    document['_id'] = str(document['_id'])
                    results.append(document)
            return {"data": results, "meta": pagination_meta}

        find_many_result = await self.execute_query(collection_name, find_many_query)

        return find_many_result if find_many_result else {"data": []}

    async def find_one(self, collection_name: str, client_id: str, _id: str = None, extra_fields: dict = None):
        if client_id is None and _id is None and extra_fields is None:
            return None

        query_filter = {}

        if client_id is not None:
            query_filter['client_id'] = client_id

        if _id is not None:
            query_filter['_id'] = ObjectId(_id)

        if extra_fields is not None:
            query_filter.update(extra_fields)

        async def find_one_query(collection):
            result = await collection.find_one(query_filter)

            if result:
                result["_id"] = str(result["_id"])

            return result if result else {}

        find_one_result = await self.execute_query(collection_name, find_one_query)

        return find_one_result if find_one_result else {}

    async def insert_one(self, collection_name: str, data: dict) -> str:
        async def insert_one_query(collection):
            result = await collection.insert_one(data)

            return str(result.inserted_id) if result else ''

        insert_one_result = await self.execute_query(collection_name, insert_one_query)

        return insert_one_result if insert_one_result else ''

    async def update_one(self, collection_name: str, client_id: str, _id: str, data: dict, extra_fields: dict = None):
        if client_id is None and _id is None and extra_fields is None:
            return None

        query_filter = {}

        if client_id is not None:
            query_filter['client_id'] = client_id

        if _id is not None:
            query_filter['_id'] = ObjectId(_id)

        if extra_fields is not None:
            query_filter.update(extra_fields)

        async def update_one_query(collection):
            result = await collection.update_one(query_filter, {"$set": data})
            existing_document = await collection.find_one(query_filter)

            if existing_document:
                existing_document["_id"] = str(existing_document["_id"])

            return existing_document if result and result.modified_count > 0 else {}

        update_one_result = await self.execute_query(collection_name, update_one_query)

        return update_one_result if update_one_result else {}
