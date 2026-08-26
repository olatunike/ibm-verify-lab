"""
IBM Verify Lab — a minimal relying-party application used to
exercise IBM Verify SaaS: OIDC login, attribute mapping,
MFA via access policy, and real-time webhooks.

Stage 1: prove the web server runs.
"""

from flask import Flask

# Create the web application object.
# __name__ tells Flask where this file lives, so it can locate
# templates and static files relative to it.
app = Flask(__name__)


# A "route" maps a URL path to a Python function.
# "/" is the site root — http://localhost:8000/
@app.route("/")
def home():
    return """
    <html>
      <body style="font-family: system-ui; padding: 40px;">
        <h1>IBM Verify Lab</h1>
        <p>Stage 1 complete — the application is running.</p>
        <p>Next: connect this app to IBM Verify for login.</p>
      </body>
    </html>
    """


# A health check. Standard practice for any deployed service:
# load balancers and monitoring call this to ask "are you alive?"
@app.route("/healthz")
def health():
    return {"status": "ok"}


# This block runs only when you execute the file directly
# (python app.py), not when something imports it.
if __name__ == "__main__":
    # Port 8000, not Flask's default 5000 — on macOS, port 5000
    # is taken by the AirPlay Receiver service.
    # host 127.0.0.1 means only this machine can reach the server.
    app.run(host="127.0.0.1", port=8000, debug=True)