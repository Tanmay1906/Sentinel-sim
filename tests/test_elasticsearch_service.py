import pytest
import uuid
from unittest.mock import MagicMock, patch
from app.services.elasticsearch_service import ElasticsearchService

@patch("elasticsearch.Elasticsearch")
def test_elasticsearch_connect_success(mock_es_class):
    # Mock connection ping success
    mock_client = MagicMock()
    mock_client.ping.return_value = True
    mock_es_class.return_value = mock_client
    
    svc = ElasticsearchService()
    assert svc.is_active is True
    assert svc.ping() is True

@patch("elasticsearch.Elasticsearch")
def test_elasticsearch_connect_ping_fail(mock_es_class):
    # Mock connection ping failure
    mock_client = MagicMock()
    mock_client.ping.return_value = False
    mock_es_class.return_value = mock_client
    
    svc = ElasticsearchService()
    assert svc.is_active is False
    assert svc.ping() is False

@patch("elasticsearch.Elasticsearch")
def test_elasticsearch_bulk_index_success(mock_es_class):
    mock_client = MagicMock()
    mock_client.ping.return_value = True
    mock_es_class.return_value = mock_client
    
    svc = ElasticsearchService()
    
    # Mock the elasticsearch helpers bulk utility
    with patch("elasticsearch.helpers.bulk") as mock_bulk:
        mock_bulk.return_value = (5, [])
        events = [{"id": "ev-1", "host": {"hostname": "win-01"}}]
        
        indexed = svc.bulk_index_events(uuid.uuid4(), events)
        assert indexed == 5
        mock_bulk.assert_called_once()
