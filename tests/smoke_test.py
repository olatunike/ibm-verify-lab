"""
smoke_test.py

Exercises the relying party's routes without a live IBM Verify tenant.

CI has no tenant and no secrets, so the app is started with placeholder
configuration. Routes that need only local logic must still answer; routes
that would call the tenant are not exercised here.

What this actually protects against: a syntax error, a broken import, a
route that raises on render, or a PKCE implementation that stops satisfying
RFC 7636. Those are exactly the regressions that would otherwise be found
by a human clicking through the app.

    python tests/smoke_test.py
"""

import base64
import hashlib
import os
import sys

# Placeholder configuration. required_env() rejects values beginning with
# "paste_" or "change_me", so these must look like real settings.
os.environ.setdefault("VERIFY_TENANT", "ci.verify.example")
os.environ.setdefault(
    "VERIFY_DISCOVERY_URL",
    "https://ci.verify.example/v1.0/endpoint/default/.well-known/openid-configuration",
)
os.environ.setdefault("VERIFY_CLIENT_ID", "ci-client-id-000000")
os.environ.setdefault("VERIFY_CLIENT_SECRET", "ci-client-secret")
os.environ.setdefault("VERIFY_REDIRECT_URI", "http://localhost:8000/callback")
os.environ.setdefault("FLASK_SECRET_KEY", "ci-only-not-a-real-key")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as lab  # noqa: E402

FAILURES = []


def check(condition, message):
    if condition:
        print("  PASS  " + message)
    else:
        print("  FAIL  " + message)
        FAILURES.append(message)


def main():
    client = lab.app.test_client()

    print("\nRoutes that need no tenant")
    print("-" * 40)

    check(client.get("/").status_code == 200, "GET / returns 200")
    check(client.get("/healthz").status_code == 200, "GET /healthz returns 200")
    check(client.get("/healthz").get_json() == {"status": "ok"},
          "GET /healthz reports ok")
    check(client.get("/pkce-demo").status_code == 200, "GET /pkce-demo returns 200")

    print("\nUnauthenticated access is redirected, not served")
    print("-" * 40)

    check(client.get("/userinfo").status_code == 302,
          "GET /userinfo without a session redirects")
    check(client.get("/raw-token").status_code == 302,
          "GET /raw-token without a session redirects")

    print("\nCallback rejects malformed requests before any network call")
    print("-" * 40)

    r = client.get("/callback?error=access_denied&error_description=policy")
    check(r.status_code == 400, "provider-reported error returns 400")

    r = client.get("/callback?code=abc&state=not-the-issued-state")
    check(r.status_code == 403, "state mismatch returns 403 (login-CSRF defence)")

    print("\nPKCE conforms to RFC 7636")
    print("-" * 40)

    verifier, challenge = lab.make_pkce_pair()

    check(43 <= len(verifier) <= 128, "verifier length within 43-128")
    check(len(challenge) == 43, "S256 challenge is 43 characters")
    check("=" not in verifier + challenge, "no base64 padding")
    check(all(c.isalnum() or c in "-_" for c in verifier + challenge),
          "base64url alphabet only")

    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )
    check(challenge == expected, "challenge is SHA-256 of the verifier")
    check(lab.make_pkce_pair()[0] != verifier, "each pair is unique")

    print("\nToken validation is not negotiable from the token header")
    print("-" * 40)

    with open(os.path.join(os.path.dirname(__file__), "..", "app.py")) as fh:
        source = fh.read()

    check('algorithms=["RS256"]' in source,
          "signing algorithm is pinned to RS256")

    # Every algorithms= argument must be the pinned literal. Reading the
    # provider's advertised list would admit alg:none and RS256/HS256
    # confusion, so no other form is acceptable anywhere in the file.
    algorithm_args = source.count("algorithms=")
    pinned_args = source.count('algorithms=["RS256"]')
    check(algorithm_args == pinned_args,
          "no algorithms= argument is anything but the pinned literal "
          "({} total, {} pinned)".format(algorithm_args, pinned_args))

    check('issuer=config["issuer"]' in source,
          "issuer is read from discovery, not constructed")
    check("audience=CLIENT_ID" in source,
          "audience is validated against this client")

    print("\n" + "=" * 40)
    if FAILURES:
        print("  {} check(s) failed".format(len(FAILURES)))
        print("=" * 40)
        return 1
    print("  all checks passed")
    print("=" * 40)
    return 0


if __name__ == "__main__":
    sys.exit(main())
