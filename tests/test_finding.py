import pytest
from unittest.mock import patch, MagicMock
from libcovulor.finding import Finding, FindingModel

findingInstance = Finding()

@pytest.fixture
def mock_db():
    return MagicMock()

def test_create_finding(mock_db):
    findingInstance.db.findings_collection = mock_db
    data = {
        "tool": "test",
        "title": "test title",
        "repo_id": "",
        "line": 1,
        "client_id": "123",
        "date": "0000-00-00",
        "description": "",
        "end_column": 0,
        "file_path": "test/test",
        "finding_id": "",
        "language": "",
        "original_line": 1,
        "severity": "",
        "start_column": 0,
        "_id": "",
    }

    mock_db.find_one.return_value = None
    mock_db.insert_one.return_value.inserted_id = "507f1f77bcf86cd799439011"

    result = findingInstance.create(data)

    assert result.object_id == "507f1f77bcf86cd799439011"
    mock_db.find_one.assert_called_once_with({'cwe': [], 'file_path': 'test/test', 'original_line': 1, 'tool': 'test'})
    mock_db.insert_one.assert_called_once()

def test_delete_finding(mock_db):
    findingInstance.db.findings_collection = mock_db
    client_id = "123"
    finding_id = "507f1f77bcf86cd799439011"
    mock_db.delete_one.return_value = {"deleted_count": 1}

    finding = FindingModel(
        tool="test",
        title="test title",
        repo_id="",
        line=1,
        client_id="",
        date="0000-00-00",
        description="",
        end_column=0,
        file_path="",
        finding_id="",
        language="",
        original_line=1,
        severity="",
        start_column=0,
        _id="507f1f77bcf86cd799439011",
    )

    with patch.object(findingInstance.db, 'delete_one', return_value=finding) as mock_delete_one:
        result = findingInstance.delete(client_id, finding_id)
        assert result == finding
        mock_delete_one.assert_called_once_with(mock_db, client_id, finding_id)

def test_delete_many_finding(mock_db):
    findingInstance.db.findings_collection = mock_db
    client_id = "123"
    mock_db.delete_one.return_value = {"deleted_count": 2}

    with patch.object(findingInstance.db, 'delete_many', return_value={"deleted_count": 2}) as mock_delete_one:
        result = findingInstance.delete_many(client_id)
        assert result == {"deleted_count": 2}
        mock_delete_one.assert_called_once_with(mock_db, client_id, None)

def test_find_many_findings(mock_db):
    findingInstance.db.findings_collection = mock_db
    client_id = "123"
    options = None
    finding1 = FindingModel(
        tool="test",
        title="test title",
        repo_id="",
        line=1,
        client_id="",
        date="0000-00-00",
        description="",
        end_column=0,
        file_path="",
        finding_id="",
        language="",
        original_line=1,
        severity="",
        start_column=0,
        _id="507f1f77bcf86cd799439011",
    )
    finding2 = FindingModel(
        tool="test",
        title="test title2",
        repo_id="",
        line=1,
        client_id="",
        date="0000-00-00",
        description="",
        end_column=0,
        file_path="",
        finding_id="",
        language="",
        original_line=1,
        severity="",
        start_column=0,
        _id="507f1f77bcf86cd799439012",
    )
    mock_db.find.return_value = {"data": [finding1, finding2]}


    with patch.object(findingInstance.db, 'find_many', return_value={"data": [finding1, finding2]}) as mock_find_many:
        result = findingInstance.find_many(client_id, options)

        assert "data" in result
        assert len(result["data"]) == 2
        mock_find_many.assert_called_once_with(mock_db, client_id, options)

def test_find_one_finding(mock_db):
    findingInstance.db.findings_collection = mock_db
    client_id = "123"
    finding_id = "507f1f77bcf86cd799439011"
    finding = FindingModel(
        tool="test",
        title="test title",
        repo_id="",
        line=1,
        client_id="",
        date="0000-00-00",
        description="",
        end_column=0,
        file_path="",
        finding_id="",
        language="",
        original_line=1,
        severity="",
        start_column=0,
        _id="507f1f77bcf86cd799439011",
    )
    mock_db.find_one.return_value = finding

    with patch.object(findingInstance.db, 'find_one', return_value=finding) as mock_find_one:
        result = findingInstance.find_one(client_id, finding_id)

        assert result == finding
        mock_find_one.assert_called_once_with(mock_db, client_id, finding_id)

def test_update_finding(mock_db):
    findingInstance.db.findings_collection = mock_db
    client_id = "123"
    finding_id = "507f1f77bcf86cd799439011"
    finding = FindingModel(
        tool="test",
        title="test title",
        repo_id="",
        line=1,
        client_id="",
        date="0000-00-00",
        description="",
        end_column=0,
        file_path="",
        finding_id="",
        language="",
        original_line=1,
        severity="",
        start_column=0,
        _id="507f1f77bcf86cd799439011",
    )
    mock_db.update_one.return_value = finding

    with patch.object(findingInstance.db, 'update_one', return_value=finding) as mock_update_one:
        result = findingInstance.update(client_id, finding_id, finding)

        assert result == finding
        mock_update_one.assert_called_once_with(mock_db, client_id, finding_id, finding)
