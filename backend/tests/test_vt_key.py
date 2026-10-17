"""The VirusTotal key source: AWS Secrets Manager in production, the VT_API_KEY setting otherwise."""

import json
import logging

import pytest
from botocore.stub import Stubber

from app.engine import virustotal, vt_key
from app.engine.virustotal import VirusTotalClient, VirusTotalUnavailable
from app.engine.vt_key import VtKeySource, VtKeyUnavailable, fetch_from_secrets_manager

ARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:VT_KEY-AbCdEf"
KEY = "f" * 64


class FakeFetch:
    def __init__(self, *results):
        self.results = list(results)
        self.calls = 0

    def __call__(self, arn, field):
        assert (arn, field) == (ARN, "VT_API_KEY")
        self.calls += 1
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def test_without_arn_the_setting_is_used():
    assert VtKeySource("", "VT_API_KEY", "from-env").get() == "from-env"


def test_secret_is_read_once_and_kept_in_memory(caplog):
    fetch = FakeFetch(KEY)
    source = VtKeySource(ARN, "VT_API_KEY", "ignored-fallback", fetch=fetch)
    with caplog.at_level(logging.INFO):
        assert source.get() == KEY
        assert source.get() == KEY
    assert fetch.calls == 1
    assert "AWS Secrets Manager (VT_KEY-AbCdEf)" in caplog.text
    assert KEY not in caplog.text  # never logged


def test_failed_read_returns_empty_and_retries_later(monkeypatch, caplog):
    fetch = FakeFetch(VtKeyUnavailable("Secrets Manager refused: AccessDeniedException"), KEY)
    source = VtKeySource(ARN, "VT_API_KEY", "", fetch=fetch)
    clock = [1000.0]
    monkeypatch.setattr(vt_key.time, "monotonic", lambda: clock[0])
    with caplog.at_level(logging.ERROR):
        assert source.get() == ""
    assert "AccessDeniedException" in caplog.text
    assert source.get() == "" and fetch.calls == 1  # no hammering
    clock[0] += vt_key.RETRY_AFTER_FAILURE_SECONDS
    assert source.get() == KEY and fetch.calls == 2


def test_rejected_key_is_re_read_after_rotation(monkeypatch):
    fetch = FakeFetch("old-key", "new-key")
    source = VtKeySource(ARN, "VT_API_KEY", "", fetch=fetch)
    clock = [1000.0]
    monkeypatch.setattr(vt_key.time, "monotonic", lambda: clock[0])
    assert source.get() == "old-key"
    source.refresh_after_rejection()  # too soon: throttled
    assert source.get() == "old-key"
    clock[0] += vt_key.REFRESH_AFTER_REJECTION_SECONDS
    source.refresh_after_rejection()
    assert source.get() == "new-key"


def test_client_re_reads_the_key_when_virustotal_says_401(monkeypatch):
    seen_keys = []

    def fake_get(url, api_key, timeout):
        seen_keys.append(api_key)
        return (401, {"error": {"code": "WrongCredentialsError"}}) if api_key == "old-key" else (404, {})

    monkeypatch.setattr(virustotal, "_http_get", fake_get)
    clock = [1000.0]
    monkeypatch.setattr(vt_key.time, "monotonic", lambda: clock[0])
    source = VtKeySource(ARN, "VT_API_KEY", "", fetch=FakeFetch("old-key", "new-key"))
    client = VirusTotalClient(source, requests_per_minute=10)
    source.get()
    clock[0] += vt_key.REFRESH_AFTER_REJECTION_SECONDS  # hours later, the secret was rotated
    with pytest.raises(VirusTotalUnavailable):
        client.lookup("domains", "a-domain.info", 60, 60)
    assert client.lookup("domains", "b-domain.info", 60, 60) is None
    assert seen_keys == ["old-key", "new-key"]


def stubbed_fetch(monkeypatch, response=None, error_code=None):
    import boto3
    real_client = boto3.client

    def make_client(*args, **kwargs):
        assert kwargs["region_name"] == "us-east-1"  # taken from the ARN
        client = real_client(*args, aws_access_key_id="x", aws_secret_access_key="y", **kwargs)
        stubber = Stubber(client)
        if error_code:
            stubber.add_client_error("get_secret_value", service_error_code=error_code)
        else:
            stubber.add_response("get_secret_value", response, {"SecretId": ARN})
        stubber.activate()
        return client

    monkeypatch.setattr(boto3, "client", make_client)


def test_fetch_reads_the_field_of_a_key_value_secret(monkeypatch):
    stubbed_fetch(monkeypatch, {"SecretString": json.dumps({"VT_API_KEY": f" {KEY} "})})
    assert fetch_from_secrets_manager(ARN, "VT_API_KEY") == KEY


def test_fetch_accepts_a_plaintext_secret(monkeypatch):
    stubbed_fetch(monkeypatch, {"SecretString": KEY})
    assert fetch_from_secrets_manager(ARN, "VT_API_KEY") == KEY


def test_fetch_missing_field(monkeypatch):
    stubbed_fetch(monkeypatch, {"SecretString": json.dumps({"OTHER": "x"})})
    with pytest.raises(VtKeyUnavailable, match="no non-empty field 'VT_API_KEY'"):
        fetch_from_secrets_manager(ARN, "VT_API_KEY")


def test_fetch_access_denied_names_the_error_not_the_value(monkeypatch):
    stubbed_fetch(monkeypatch, error_code="AccessDeniedException")
    with pytest.raises(VtKeyUnavailable, match="AccessDeniedException"):
        fetch_from_secrets_manager(ARN, "VT_API_KEY")
