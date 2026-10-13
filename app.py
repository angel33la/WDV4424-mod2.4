from flask import Flask, render_template, session, redirect, url_for, jsonify
from datetime import timedelta
from werkzeug.exceptions import HTTPException
import json
from os import environ as env
from urllib.parse import quote_plus, urlencode
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv, find_dotenv
from functools import wraps

# Load environment variables from .env file
load_dotenv(find_dotenv())

app = Flask(__name__)
oauth = OAuth(app)
app.secret_key = "apples"
app.debug = True
AUTH_BASE_URL = env.get('AUTH0_BASE_URL')

# Auth0 Configuration
auth0 = oauth.register(
    'auth0',
    client_id=env.get('AUTH0_CLIENT_ID'),
    client_secret=env.get('AUTH0_CLIENT_SECRET'),
    api_base_url=AUTH_BASE_URL,
    access_token_url=AUTH_BASE_URL + '/oauth/token',
    authorize_url=AUTH_BASE_URL + '/authorize',
    client_kwargs={"scope": "openid profile email"},
    server_metadata_url=AUTH_BASE_URL + "/.well-known/openid-configuration"
)

app.config['SESSION_TYPE'] = 'filesystem'

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

# Error Handler (Now safely uses Flask's jsonify function)
@app.errorhandler(Exception)
def handle_exception(ex):
    response = jsonify({"message": str(ex)})
    response.status_code = (ex.code if isinstance(ex, HTTPException) else 500)
    return response

# Auth0 Callback Route
@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = auth0.authorize_access_token()
    session["user"] = token
    resp = auth0.get("userinfo")
    print(resp)
    return redirect("/dashboard")

# Login Route
@app.route('/login')
def login():
    return auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True, _scheme="http"))

# Authentication
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        print(session)
        if 'user' not in session:
            return redirect('/home')
        return f(*args, **kwargs)
    return decorated

# Protected Dashboard Route
@app.route('/dashboard')
@requires_auth
def dashboard():
    return render_template(
        'dashboard.html',
        session=session.get("user"),
        pretty=json.dumps(session.get("user"), indent=4)
    )

# Protected Settings Route
@app.route('/settings')
@requires_auth
def settings():
    user_data = session.get('user', {}).get('userinfo', {})

    nickname = user_data.get('nickname')
    picture = user_data.get('picture')

    # Save the nickname to the session
    session['nickname'] = nickname

    return render_template(
        'settings.html',
        nickname=nickname,
        picture=picture
    )

# Home / Welcome Route
@app.route('/home')
def hello():
    print("hello, you're at home")
    return render_template(
        'home.html',
        session=session.get("user"),
        pretty=json.dumps(session.get("user"), indent=4)
    )

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)
