from .database import repositories_collection
from bson.objectid import ObjectId
from pydantic import BaseModel, Field
from pymongo.errors import PyMongoError

class Repository:
    ACTIVE = 'active'
    AUTH = 'repository_auth'
    BRANCH = 'repository_branch'
    CLIENT_ID = 'client_id'
    DESCRIPTION = 'description'
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

    @staticmethod
    def create_repository(data: dict):
        try:
            existing_document = repositories_collection.find_one({Repository.URL: data["uri"]})

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
                Repository.AUTH: data['github_oauth_token'],
                Repository.PROCESSING_STATUS: "processing",
                Repository.BRANCH: data["data"]["git_connection"]["repo_branch"],
                Repository.SOURCE_CONTROL: data['source_control'],
                Repository.PRIORITY: data[Repository.PRIORITY],
                Repository.TAGS: data[Repository.TAGS]
            }
            repository = repositories_collection.insert_one(repo_document)

            return str(repository.inserted_id) if repository.inserted_id else None
        except PyMongoError as e:
            print(f'Error: {e}')

            return None

class RepositoryModel(BaseModel):
    _id: ObjectId = Field(exclude=True, alias='_id')
