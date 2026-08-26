"""
IBM Verify Lab — a minimal application used to exercise
IBM Verify SaaS features: OIDC login, attribute mapping,
access policies and real-time webhooks.

Stage 1: prove the web server runs.
"""

from flask import Flask

# Create the web application object.
# __name__ tells Flask where this file lives so it can find
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
# load balancers and monitoring systems call this to ask
# "are you alive?" without needing a real page.
@app.route("/healthz")
def health():
    return {"status": "ok"}


# This block only runs when you execute the file directly
# (python app.py), not when something imports it.
if __name__ == "__main__":
    # port 8000, NOT 5000 — see the note below
    app.run(host="127.0.0.1", port=8000, debug=True)

    # Python virtual environment — never commit; it's machine-specific
.venv/
__pycache__/
*.pyc

# Secrets — NEVER commit
.env

# macOS clutter
.DS_Store
