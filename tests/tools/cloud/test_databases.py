"""tests/tools/cloud/test_databases.py - unit tests for tools/cloud/databases/"""

from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch

import pytest

from models import Severity
from tools.cloud.databases.couchdb import check_couchdb
from tools.cloud.databases.elasticsearch import check_elasticsearch
from tools.cloud.databases.mongodb import check_mongodb
from tools.cloud.databases.redis import check_redis
from tools.cloud.databases.sql import check_mysql, check_postgresql

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Elasticsearch
# ---------------------------------------------------------------------------


class TestCheckElasticsearch:
    def test_returns_critical_when_unauthenticated(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"cluster_name":"prod","status":"green"}'
        with patch("requests.get", return_value=mock_resp):
            results = check_elasticsearch("es.example.com")
        assert len(results) == 1
        assert results[0].severity_hint == Severity.CRITICAL
        assert results[0].vuln_class == "ExposedService"
        assert "Elasticsearch" in results[0].title

    def test_probes_health_endpoint_with_pinned_call_args(self):
        # Pin the outbound call: a mutated URL, timeout, or allow_redirects
        # silently changes what we probe. The probe hits the cluster-health
        # endpoint on 9200, with a short timeout and redirects disabled.
        calls: list[tuple[str, dict]] = []

        def recording_get(url, **kwargs):
            calls.append((url, kwargs))
            resp = MagicMock()
            resp.status_code = 200
            resp.text = '{"cluster_name":"prod"}'
            return resp

        with patch("requests.get", side_effect=recording_get):
            check_elasticsearch("es.example.com")

        assert len(calls) == 1
        url, kwargs = calls[0]
        assert url == "http://es.example.com:9200/_cluster/health"
        assert kwargs["timeout"] == 5
        assert kwargs["allow_redirects"] is False

    def test_finding_fields_are_fully_pinned(self):
        # A long body proves evidence carries the response excerpt (and the
        # exact [:300] truncation boundary), not a fixed string.
        body = '{"cluster_name":"' + "x" * 400 + '"}'
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = body
        with patch("requests.get", return_value=mock_resp):
            results = check_elasticsearch("es.example.com")

        assert len(results) == 1
        f = results[0]
        assert f.title == "Unauthenticated Elasticsearch - es.example.com"
        assert f.target == "http://es.example.com:9200/_cluster/health"
        assert f.vuln_class == "ExposedService"
        assert f.tool == "elasticsearch_check"
        assert f.severity_hint == Severity.CRITICAL
        assert f.evidence == (
            f"Elasticsearch responded without authentication.\nResponse: {body[:300]}"
        )

    def test_no_finding_on_403(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "Unauthorized"
        with patch("requests.get", return_value=mock_resp):
            assert check_elasticsearch("es.example.com") == []

    def test_no_finding_when_marker_absent(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"status":"green"}'  # no cluster_name
        with patch("requests.get", return_value=mock_resp):
            assert check_elasticsearch("es.example.com") == []

    def test_exception_is_swallowed(self):
        with patch("requests.get", side_effect=Exception("refused")):
            assert check_elasticsearch("es.example.com") == []


# ---------------------------------------------------------------------------
# CouchDB
# ---------------------------------------------------------------------------


class TestCheckCouchdb:
    def test_returns_critical_when_unauthenticated(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '["_users","_replicator","mydb"]'
        with patch("requests.get", return_value=mock_resp):
            results = check_couchdb("couch.example.com")
        assert len(results) == 1
        assert results[0].severity_hint == Severity.CRITICAL
        assert "CouchDB" in results[0].title

    def test_no_finding_when_status_200_but_marker_absent(self):
        # 200 with no database-list marker ("[") must NOT be reported: the
        # guard is status AND marker, so a bare 200 (e.g. an auth-gated
        # landing page) is not an unauthenticated listing. Kills the
        # and->or mutation on the guard.
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "Welcome to Apache CouchDB"  # no '['
        with patch("requests.get", return_value=mock_resp):
            assert check_couchdb("couch.example.com") == []

    def test_probes_all_dbs_endpoint_with_pinned_call_args(self):
        calls: list[tuple[str, dict]] = []

        def recording_get(url, **kwargs):
            calls.append((url, kwargs))
            resp = MagicMock()
            resp.status_code = 200
            resp.text = '["_users"]'
            return resp

        with patch("requests.get", side_effect=recording_get):
            check_couchdb("couch.example.com")

        assert len(calls) == 1
        url, kwargs = calls[0]
        assert url == "http://couch.example.com:5984/_all_dbs"
        assert kwargs["timeout"] == 5
        assert kwargs["allow_redirects"] is False

    def test_finding_fields_are_fully_pinned(self):
        body = "[" + "x" * 400  # long, marker-bearing body
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = body
        with patch("requests.get", return_value=mock_resp):
            results = check_couchdb("couch.example.com")

        assert len(results) == 1
        f = results[0]
        assert f.title == "Unauthenticated CouchDB - couch.example.com"
        assert f.target == "http://couch.example.com:5984/_all_dbs"
        assert f.vuln_class == "ExposedService"
        assert f.tool == "couchdb_check"
        assert f.severity_hint == Severity.CRITICAL
        assert f.evidence == (
            f"CouchDB listed all databases without authentication.\nResponse: {body[:300]}"
        )

    def test_no_finding_on_401(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = "Unauthorized"
        with patch("requests.get", return_value=mock_resp):
            assert check_couchdb("couch.example.com") == []

    def test_exception_is_swallowed(self):
        with patch("requests.get", side_effect=Exception("timeout")):
            assert check_couchdb("couch.example.com") == []


# ---------------------------------------------------------------------------
# Redis
# ---------------------------------------------------------------------------


def _mock_socket(recv_data: bytes):
    """Return a mock socket context manager that yields recv_data."""
    mock_sock = MagicMock()
    mock_sock.recv.return_value = recv_data
    mock_sock.__enter__ = lambda s: s
    mock_sock.__exit__ = MagicMock(return_value=False)
    return mock_sock


class TestCheckRedis:
    def test_returns_critical_on_pong(self):
        with patch("socket.create_connection", return_value=_mock_socket(b"+PONG\r\n")):
            results = check_redis("cache.example.com")
        assert len(results) == 1
        assert results[0].severity_hint == Severity.CRITICAL
        assert "Redis" in results[0].title

    def test_no_finding_when_auth_required(self):
        with patch("socket.create_connection", return_value=_mock_socket(b"-NOAUTH\r\n")):
            assert check_redis("cache.example.com") == []

    def test_exception_is_swallowed(self):
        with patch("socket.create_connection", side_effect=socket.timeout):
            assert check_redis("cache.example.com") == []


# ---------------------------------------------------------------------------
# MongoDB
# ---------------------------------------------------------------------------


class TestCheckMongodb:
    def test_returns_critical_on_ismaster_response(self):
        response = b"\x00" * 20 + b"ismaster" + b"\x00" * 10
        with patch("socket.create_connection", return_value=_mock_socket(response)):
            results = check_mongodb("mongo.example.com")
        assert len(results) == 1
        assert results[0].severity_hint == Severity.CRITICAL
        assert "MongoDB" in results[0].title

    def test_returns_critical_on_iswritableprimary_response(self):
        response = b"\x00" * 20 + b"isWritablePrimary" + b"\x00" * 10
        with patch("socket.create_connection", return_value=_mock_socket(response)):
            results = check_mongodb("mongo.example.com")
        assert len(results) == 1

    def test_no_finding_on_empty_response(self):
        with patch("socket.create_connection", return_value=_mock_socket(b"")):
            assert check_mongodb("mongo.example.com") == []

    def test_exception_is_swallowed(self):
        with patch("socket.create_connection", side_effect=ConnectionRefusedError):
            assert check_mongodb("mongo.example.com") == []


# ---------------------------------------------------------------------------
# PostgreSQL
# ---------------------------------------------------------------------------


def _pg_auth_response(method: int) -> bytes:
    """Build a minimal PostgreSQL AuthenticationRequest message."""
    # 'R' + length(4) + method(4)
    return b"R" + (8).to_bytes(4, "big") + method.to_bytes(4, "big")


class TestCheckPostgresql:
    def test_returns_critical_on_trust_auth(self):
        with patch("socket.create_connection", return_value=_mock_socket(_pg_auth_response(0))):
            results = check_postgresql("db.example.com")
        assert len(results) == 1
        assert results[0].severity_hint == Severity.CRITICAL
        assert "Unauthenticated" in results[0].title

    def test_returns_medium_on_auth_required(self):
        # method 5 = MD5 password required
        with patch("socket.create_connection", return_value=_mock_socket(_pg_auth_response(5))):
            results = check_postgresql("db.example.com")
        assert len(results) == 1
        assert results[0].severity_hint == Severity.MEDIUM
        assert "Exposed" in results[0].title

    def test_no_finding_on_empty_response(self):
        with patch("socket.create_connection", return_value=_mock_socket(b"")):
            assert check_postgresql("db.example.com") == []

    def test_exception_is_swallowed(self):
        with patch("socket.create_connection", side_effect=ConnectionRefusedError):
            assert check_postgresql("db.example.com") == []


# ---------------------------------------------------------------------------
# MySQL / MariaDB
# ---------------------------------------------------------------------------


def _mysql_greeting(version: str = "8.0.28") -> bytes:
    """Build a minimal MySQL protocol v10 server greeting."""
    version_bytes = version.encode() + b"\x00"
    # 4-byte packet header + \x0a (protocol v10) + version + null + padding
    payload = b"\x0a" + version_bytes + b"\x00" * 20
    length = len(payload).to_bytes(3, "little")
    return length + b"\x00" + payload


class TestCheckMysql:
    def test_returns_medium_on_valid_greeting(self):
        with patch("socket.create_connection", return_value=_mock_socket(_mysql_greeting())):
            results = check_mysql("db.example.com")
        assert len(results) == 1
        assert results[0].severity_hint == Severity.MEDIUM
        assert "MySQL" in results[0].title

    def test_detects_mariadb_string(self):
        mariadb_data = b"\x20\x00\x00\x00" + b"\xff" + b"5.5.5-10.6.0-MariaDB\x00" + b"\x00" * 20
        with patch("socket.create_connection", return_value=_mock_socket(mariadb_data)):
            results = check_mysql("db.example.com")
        assert len(results) == 1
        assert "MySQL" in results[0].title

    def test_no_finding_on_unrecognised_response(self):
        with patch("socket.create_connection", return_value=_mock_socket(b"\xff\xff\xff\xff")):
            assert check_mysql("db.example.com") == []

    def test_exception_is_swallowed(self):
        with patch("socket.create_connection", side_effect=ConnectionRefusedError):
            assert check_mysql("db.example.com") == []
