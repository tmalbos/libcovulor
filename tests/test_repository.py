import pytest
from unittest.mock import patch, MagicMock
from libcovulor.repository import Repository, RepositoryModel

repositoryInstance = Repository()

@pytest.fixture
def mock_db():
    return MagicMock()

@pytest.mark.asyncio
@patch.object(Repository, 'create')
async def test_create_repository(mock_db):
    data = {
        "_id": "507f1f77bcf86cd799439011",
        "uri": "http://example.com/repo.git",
        "client_id": "123",
        "type": "git",
        "nickname": "example_repo",
        "description": "An example repository",
        "github_oauth_token": "token",
        "data": {
            "git_connection": {
                "repo_branch": "main"
            }
        },
        "source_control": "github",
        "priority": "high",
        "tags": ["example", "repo"]
    }
    mock_db.return_value = data

    result = await repositoryInstance.create(data)

    assert result['_id'] == data['_id']
    repositoryInstance.create.assert_called_once_with(data)
    mock_db.assert_called_once()

@pytest.mark.asyncio
@patch.object(Repository, 'find_one')
async def test_create_repository_already_exists(mock_db):
    data = {"uri": "http://example.com/repo.git"}
    mock_db.return_value = None

    result = await repositoryInstance.find_one(data)
    assert result is None

@pytest.mark.asyncio
async def test_delete_repository(mock_db):
    repositoryInstance.db.repositories_collection = mock_db
    client_id = "123"
    repository_id = "507f1f77bcf86cd799439011"
    repository = RepositoryModel(_id=repository_id, client_id=client_id)
    mock_db.delete_one.return_value = repository

    with patch.object(repositoryInstance.db, 'delete_one', return_value=repository) as mock_delete_one:
        result = await repositoryInstance.delete(client_id, repository_id)

        assert result == repository
        mock_delete_one.assert_called_once_with(mock_db, client_id, repository_id)

@pytest.mark.asyncio
async def test_delete_many_finding(mock_db):
    repositoryInstance.db.repositories_collection = mock_db
    client_id = "123"
    mock_db.delete_one.return_value = {"deleted_count": 2}

    with patch.object(repositoryInstance.db, 'delete_many', return_value={"deleted_count": 2}) as mock_delete_one:
        result = await repositoryInstance.delete_many(client_id)
        assert result == {"deleted_count": 2}
        mock_delete_one.assert_called_once_with(mock_db, client_id, None)

@pytest.mark.asyncio
async def test_find_many_repositories(mock_db):
    repositoryInstance.db.repositories_collection = mock_db
    client_id = "123"
    options = None
    repository1 = RepositoryModel(_id="507f1f77bcf86cd799439011", client_id=client_id, alias="repo1")
    repository2 = RepositoryModel(_id="507f1f77bcf86cd799439012", client_id=client_id, alias="repo2")
    mock_db.find.return_value = {"data": [repository1, repository2]}

    with patch.object(repositoryInstance.db, 'find_many', return_value={"data": [repository1, repository2]}) as mock_find_many:
        result = await repositoryInstance.find_many(client_id, options)

        assert "data" in result
        assert len(result["data"]) == 2
        mock_find_many.assert_called_once_with(mock_db, client_id, options)

@pytest.mark.asyncio
async def test_find_one_repository(mock_db):
    repositoryInstance.db.repositories_collection = mock_db
    client_id = "123"
    repository_id = "507f1f77bcf86cd799439011"
    repository = RepositoryModel(_id=repository_id, client_id=client_id, alias="repo")
    mock_db.find_one.return_value = repository

    with patch.object(repositoryInstance.db, 'find_one', return_value=repository) as mock_find_one:
        result = await repositoryInstance.find_one(client_id, repository_id)

        assert result == repository
        mock_find_one.assert_called_once_with(mock_db, client_id, repository_id)

@pytest.mark.asyncio
async def test_update_repository(mock_db):
    repositoryInstance.db.repositories_collection = mock_db
    client_id = "123"
    repository_id = "507f1f77bcf86cd799439011"
    repository = RepositoryModel(_id=repository_id, client_id=client_id, alias="repo new name")
    mock_db.update_one.return_value = repository

    with patch.object(repositoryInstance.db, 'update_one', return_value=repository) as mock_update_one:
        result = await repositoryInstance.update(client_id, repository_id, repository)

        assert result == repository
        mock_update_one.assert_called_once_with(mock_db, client_id, repository_id, repository)
