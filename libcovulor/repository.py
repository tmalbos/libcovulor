from .database import Database, MongoDBClient
from pydantic import BaseModel, Field
from pymongo.errors import PyMongoError

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

    def __init__(self, mongodb_server: str = "mongodb://mongodb", port: int = 27017, db_name: str = "plexicus"):
        self.db = Database(mongodb_server, port, db_name)
        self.mongo = MongoDBClient(mongodb_server, port, db_name)

    def create(self, data: dict):
        try:
            with self.mongo:
                existing_document = self.mongo.get_collection(self.db.repositories_collection).find_one({Repository.URL: data["uri"]})

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
                    Repository.TAGS: data[Repository.TAGS]
                }
                repository = self.mongo.get_collection(self.db.repositories_collection).insert_one(repo_document)

                return str(repository.inserted_id) if repository.inserted_id else None
        except PyMongoError as e:
            print(f'Error: {e}')

            return None

    def delete(self, client_id: str, repository_id: str):
        dict_repository = self.db.delete_one(self.db.repositories_collection, client_id, repository_id)
        # return RepositoryModel.parse_obj(dict_repository)
        return dict_repository

    def delete_many(self, client_id: str, options: dict = None):
        dict_finding = self.db.delete_many(self.db.repositories_collection, client_id, options)

        return dict_finding

    def find_many(self, client_id: str, options: dict = None):
        repositories = self.db.find_many(self.db.repositories_collection, client_id, options)
        model_data = []

        for repo in repositories['data']:
            #model_repository = RepositoryModel.parse_obj(repo['attributes'])
            model_repository = repo
            model_data.append(model_repository)

        repositories['data'] = model_data

        return repositories

    def find_one(self, client_id: str, repository_id: str):
        dict_repository = self.db.find_one(self.db.repositories_collection, client_id, repository_id)
        # return RepositoryModel.parse_obj(dict_repository)
        return dict_repository

    def update(self, client_id: str, repository_id: str, data: dict):
        dict_repository = self.db.update_one(self.db.repositories_collection, client_id, repository_id, data)
        # return RepositoryModel.parse_obj(dict_finding)
        return dict_repository

class RepositoryModel(BaseModel):
    object_id: str = Field(exclude=True, alias='_id')
