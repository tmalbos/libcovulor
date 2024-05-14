from libcovulor import Repository
import os
from pymongo import MongoClient

# repo = Repository(mongodb_server=os.getenv('MONGODB_SERVER', 'mongodb://localhost'))
client = MongoClient(os.getenv('MONGODB_SERVER', 'mongodb://localhost'), 27017)
repo = Repository(client=client)

data_create = {
    "active": True,
    "client_id": "65f079f3ef898e6a6bb37e5b",
    "nickname": "plexicus/simple-vulnerable",
    "description": "",
    "uri": "https://github.com/plexicus/simple-vulnerable",
    "type": "git_repository",
    "github_oauth_token": os.getenv('TOKEN', ''),
    "data": {
        "git_connection": {
            "repo_url": "https://github.com/plexicus/simple-vulnerable",
            "repo_token": "",
            "repo_branch": "main"
        }
    }
}
print("---------------------- Repository List")
print(repo.get_repositories_by_client_id('65f079f3ef898e6a6bb37e5b', {"pagination": {
      "page_size": 1, "page": 2, "paginate": False}, "filters": {"active": True, "repository_type": "git_repository"}, "sort": {"order": -1, "field": "alias"}}))

print("---------------------- Repository create")
id = repo.create_repository(data_create)
print(id)

print("---------------------- Repository update")
print(repo.update_repository_by_id_and_client_id(
    {'active': False}, id, '65f079f3ef898e6a6bb37e5b'))

print("---------------------- Repository by id and client id")
print(repo.get_repository_by_id_and_client_id(
    {'repository_id': id, 'client_id': '65f079f3ef898e6a6bb37e5b'}))

print("---------------------- Repository delete")
print(repo.delete_repository_by_id_and_client_id(id, '65f079f3ef898e6a6bb37e5b'))
repo.close_connection()
