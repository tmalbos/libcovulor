from .database import Database, MongoDBClient
from pydantic import BaseModel, Field
from pymongo.errors import PyMongoError
from bson import ObjectId

import logging

class Repository:
    ACTIVE = 'active'
    BRANCH = 'repository_branch'
    CLIENT_ID = 'client_id'
    DESCRIPTION = 'description'
    ID = 'repository_id'
    NAME = 'alias'
    PRIORITY = 'priority'
    PROCESSING_STATUS = 'processing_status'
    SOURCE_CONTROL = 'source_control'
    TAGS = 'tags'
    TICKET_API_URL = 'ticket_api_url'
    TICKET_AUTH = 'ticket_auth'
    TICKET_PROVIDER_TYPE = 'ticket_provider_type'
    TYPE = 'repository_type'
    URL = 'url'
    STATUS = 'status'

    def __init__(self, database_username=None, database_password=None, database_host="mongodb", port: int = 27017, database_options=None, db_name="plexicus"):
        self.db = Database(database_username, database_password, database_host, port, database_options, db_name)
        self.db_username = database_username
        self.db_password = database_password
        self.db_host = database_host
        self.db_port = port
        self.db_options = database_options
        self.db_name = db_name

    async def create(self, data: dict):
        existing_document = await self.db.find_one(self.db.repositories_collection, data[Repository.CLIENT_ID], extra_fields={Repository.URL: data["uri"]})

        if existing_document:
            return None

        repo_document = {
            Repository.ACTIVE: True,
            Repository.URL: data["uri"],
            Repository.CLIENT_ID: data[Repository.CLIENT_ID],
            Repository.TYPE: data["type"],
            Repository.NAME: data["nickname"],
            Repository.TICKET_PROVIDER_TYPE: None,
            Repository.TICKET_AUTH: None,
            Repository.TICKET_API_URL: None,
            Repository.DESCRIPTION: data[Repository.DESCRIPTION],
            Repository.PROCESSING_STATUS: "processing",
            Repository.BRANCH: data["data"]["git_connection"]["repo_branch"],
            Repository.SOURCE_CONTROL: data[Repository.SOURCE_CONTROL],
            Repository.PRIORITY: data[Repository.PRIORITY],
            Repository.TAGS: data[Repository.TAGS],
            Repository.STATUS: data[Repository.STATUS]
        }
        repository = await self.db.insert_one(self.db.repositories_collection, repo_document)

        # TODO FIX: The repository and finding classes are returning different types of values

        return repository if repository else None

    async def delete(self, client_id: str, repository_id: str):
        dict_repository = await self.db.delete_one(self.db.repositories_collection, client_id, repository_id)
        # return RepositoryModel.parse_obj(dict_repository)
        return dict_repository

    async def delete_many(self, client_id: str, options: dict = None):
        dict_finding = await self.db.delete_many(self.db.repositories_collection, client_id, options)

        return dict_finding

    async def find_many(self, client_id: str, options: dict = None):
        repositories = await self.db.find_many(self.db.repositories_collection, client_id, options)
        model_data = []

        for repo in repositories['data']:
            #model_repository = RepositoryModel.parse_obj(repo['attributes'])
            model_repository = repo
            model_data.append(model_repository)

        repositories['data'] = model_data

        return repositories

    async def find_one(self, client_id: str, repository_id: str):
        dict_repository = await self.db.find_one(self.db.repositories_collection, client_id, repository_id)
        # return RepositoryModel.parse_obj(dict_repository)
        return dict_repository

    async def update(self, client_id: str, repository_id: str, data: dict):
        dict_repository = await self.db.update_one(self.db.repositories_collection, client_id, repository_id, data)
        # return RepositoryModel.parse_obj(dict_finding)
        return dict_repository

class RepositoryModel(BaseModel):
    object_id: str = Field(exclude=True, alias='_id')
