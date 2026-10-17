import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.main import app
from app.security import GoogleIdentityVerifier
from tests.conftest import BENIGN_REPORT, TEST_AUDIENCE, TEST_EMAIL

GOOGLE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_token(key=GOOGLE_KEY, **overrides) -> str:
    now = int(time.time())
    claims = {
        "iss": "https://accounts.google.com",
        "aud": TEST_AUDIENCE,
        "email": TEST_EMAIL,
        "email_verified": True,
        "iat": now,
        "exp": now + 3600,
        **overrides,
    }
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm="RS256")


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def client():
    with TestClient(app) as c:
        # Stand in for Google's key endpoint: tokens are checked against our test key pair.
        app.state.verifier = GoogleIdentityVerifier(
            [TEST_AUDIENCE], [TEST_EMAIL], key_resolver=lambda token: GOOGLE_KEY.public_key()
        )
        yield c


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_analyze_with_valid_token(client):
    response = client.post("/analyze", json=BENIGN_REPORT, headers=auth(make_token()))
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "safe"
    assert {"score", "summary", "findings", "rulesEvaluated", "rulesFailed"} <= body.keys()
    assert (body["suspiciousThreshold"], body["maliciousThreshold"]) == (30, 70)  # for the card's range line


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Basic abc"},
        {"Authorization": "Bearer"},
        {"Authorization": "Bearer not-a-jwt"},
        {"Authorization": "Bearer " + "a" * 5000},
    ],
)
def test_missing_or_malformed_token_rejected(client, headers):
    assert client.post("/analyze", json=BENIGN_REPORT, headers=headers).status_code == 401


@pytest.mark.parametrize(
    "token",
    [
        make_token(aud="some-other-app.apps.googleusercontent.com"),  # issued to another app
        make_token(iss="https://evil.example"),
        make_token(exp=int(time.time()) - 3600, iat=int(time.time()) - 7200),  # expired
        make_token(email=None),
        make_token(key=OTHER_KEY),  # not signed by Google
        jwt.encode({"aud": TEST_AUDIENCE, "email": TEST_EMAIL}, key=None, algorithm="none"),
    ],
    ids=["wrong-audience", "wrong-issuer", "expired", "no-email", "forged-signature", "alg-none"],
)
def test_invalid_token_rejected(client, token):
    assert client.post("/analyze", json=BENIGN_REPORT, headers=auth(token)).status_code == 401


@pytest.mark.parametrize(
    "token",
    [make_token(email="stranger@example.com"), make_token(email_verified=False)],
    ids=["not-allowlisted", "unverified-email"],
)
def test_valid_token_for_disallowed_account_forbidden(client, token):
    assert client.post("/analyze", json=BENIGN_REPORT, headers=auth(token)).status_code == 403


@pytest.mark.parametrize(
    ("policy", "email", "allowed"),
    [
        (["*"], "anyone@gmail.com", True),
        (["*@corp.example"], "alice@corp.example", True),
        (["*@corp.example"], "alice@evil-corp.example", False),
        (["*@corp.example"], "alice@sub.corp.example", False),
        (["bob@x.com"], "bob@x.com", True),
    ],
)
def test_email_policy(policy, email, allowed):
    verifier = GoogleIdentityVerifier([TEST_AUDIENCE], policy, key_resolver=lambda token: GOOGLE_KEY.public_key())
    token = make_token(email=email)
    if allowed:
        assert verifier.verify(token) == email
    else:
        with pytest.raises(Exception, match="not allowed"):
            verifier.verify(token)


def test_wildcard_still_requires_our_audience():
    verifier = GoogleIdentityVerifier([TEST_AUDIENCE], ["*"], key_resolver=lambda token: GOOGLE_KEY.public_key())
    with pytest.raises(Exception, match="Invalid token"):
        verifier.verify(make_token(aud="another-app.apps.googleusercontent.com"))


def test_auth_checked_before_body_validation(client):
    # An unauthenticated caller learns nothing about the schema.
    assert client.post("/analyze", json={"junk": True}).status_code == 401


def test_oversized_request_rejected(client):
    payload = json.dumps({**BENIGN_REPORT, "padding": "x" * 2_000_000})
    response = client.post(
        "/analyze",
        content=payload,
        headers={**auth(make_token()), "Content-Type": "application/json"},
    )
    assert response.status_code == 413


def test_validation_error_does_not_echo_input(client):
    bad = {**BENIGN_REPORT, "links": [{"url": "https://x", "text": "SECRET-CONTENT", "source": "bogus"}]}
    response = client.post("/analyze", json=bad, headers=auth(make_token()))
    assert response.status_code == 422
    assert "SECRET-CONTENT" not in response.text


def test_rules_endpoint_lists_rules_for_settings(client):
    assert client.get("/rules").status_code == 401
    rules = client.get("/rules", headers=auth(make_token())).json()
    by_id = {r["id"]: r for r in rules}
    assert by_id["user_blocklist"]["canDisable"] is False
    vt = by_id["virustotal_domain"]
    assert (vt["category"], vt["score"], vt["canDisable"]) == ("domain", 65, True)
    assert vt["description"].startswith("A domain in the email")
    assert all(r["description"] for r in rules)  # every rule explains itself in the add-on


def test_preferences_are_bounded(client):
    report = json.loads(json.dumps(BENIGN_REPORT))
    report["preferences"] = {"blockedSenders": [f"x{i}.com" for i in range(201)]}
    assert client.post("/analyze", json=report, headers=auth(make_token())).status_code == 422


def test_gauge_is_a_public_cacheable_animated_gif(client):
    response = client.get("/gauge/45.gif")  # no token: Gmail's image proxy fetches it
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/gif"
    assert "immutable" in response.headers["cache-control"]
    assert response.content[:6] == b"GIF89a"
    from io import BytesIO
    from PIL import Image
    image = Image.open(BytesIO(response.content))
    assert image.size == (560, 200) and image.n_frames > 5
    assert "loop" not in image.info  # plays once, then holds the final frame


@pytest.mark.parametrize("path", ["/gauge/101.gif", "/gauge/-1.gif", "/gauge/abc.gif"])
def test_gauge_rejects_out_of_range_scores(client, path):
    assert client.get(path).status_code == 422


@pytest.mark.parametrize("rule_id", ["BAD", "a-b", "x" * 65, "<script>", "", "1rule"])
def test_malformed_rule_ids_are_rejected(client, rule_id):
    report = json.loads(json.dumps(BENIGN_REPORT))
    report["preferences"] = {"disabledRules": [rule_id]}
    assert client.post("/analyze", json=report, headers=auth(make_token())).status_code == 422


def test_unknown_but_well_formed_rule_id_is_accepted_and_ignored(client):
    report = json.loads(json.dumps(BENIGN_REPORT))
    report["preferences"] = {"disabledRules": ["no_such_rule"]}
    assert client.post("/analyze", json=report, headers=auth(make_token())).status_code == 200
