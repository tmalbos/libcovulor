from .database import delete_one, find_many, find_one, repositories_collection, update_one
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
    def create(data: dict):
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

    @staticmethod
    def delete(client_id: str, finding_id: str):
        dict_finding = delete_one(repositories_collection, client_id, finding_id)
        # return RepositoryModel.parse_obj(dict_finding)
        return dict_finding

    @staticmethod
    def find_many(client_id: str, options: dict = None):
        findings = find_many(repositories_collection, client_id, options)
        model_data = []

        for finding in findings['data']:
            #model_finding = RepositoryModel.parse_obj(finding)
            model_finding = finding
            model_data.append(model_finding)

        findings['data'] = model_data

        return findings

    @staticmethod
    def find_one(client_id: str, finding_id: str):
        dict_finding = find_one(repositories_collection, client_id, finding_id)
        # return RepositoryModel.parse_obj(dict_finding)
        return dict_finding

    @staticmethod
    def update(client_id: str, finding_id: str, data: dict):
        dict_finding = update_one(repositories_collection, client_id, finding_id, data)
        # return RepositoryModel.parse_obj(dict_finding)
        return dict_finding

class RepositoryModel(BaseModel):
    object_id: str = Field(exclude=True, alias='_id')
