# Copyright 2019 British Broadcasting Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
from flask import request, session, send_from_directory, g
from flask import render_template, redirect, url_for, jsonify, abort
from werkzeug.security import gen_salt
from jinja2 import FileSystemLoader, ChoiceLoader
from functools import wraps
from authlib.oauth2.rfc6749 import OAuth2Error, InvalidRequestError
from nmoscommon.webapi import WebAPI, route
from nmoscommon.auth.nmos_auth import RequiresAuth

from .models import db, OAuth2Client, ResourceOwner
from .oauth2 import authorization
from .app import config_app
from .db_utils import addAdminUser, addResourceOwner, getAdminUser, getResourceOwner
from .db_utils import removeClient, removeResourceOwner
from .constants import CERT_PATH

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

APINAMESPACE = "x-nmos"
APINAME = "auth"
APIVERSION = "v1.0"

AUTH_API_ROOT = '/{}/{}'.format(APINAMESPACE, APINAME)
AUTH_VERSION_ROOT = '{}/{}/'.format(AUTH_API_ROOT, APIVERSION)


class SecurityAPI(WebAPI):
    def __init__(self, logger, nmosConfig, confClass, extraConfig=None):
        super(SecurityAPI, self).__init__()
        self._config = nmosConfig
        self.logger = logger
        self.add_templates_folder()
        config_app(self.app, confClass=confClass, config=extraConfig)  # OAuth and DB config

    # Add html templates folder to list of Jinja loaders
    def add_templates_folder(self):
        my_loader = ChoiceLoader([
            self.app.jinja_loader,
            FileSystemLoader(SCRIPT_DIR + '/static'),
            FileSystemLoader(SCRIPT_DIR + '/templates')
        ])
        self.app.jinja_loader = my_loader

    def admin_required(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            user = None
            if 'id' in session:
                uid = session['id']
                user = getAdminUser(uid)
            elif request.authorization:
                username = request.authorization.username
                user = getAdminUser(username)
                if not user or not user.check_password(request.authorization.password):
                    abort(401)
            g.user = user
            if not user:
                if "Accept" in request.headers and "text/html" in request.headers.get("Accept"):
                    session["redirect"] = request.url
                    return redirect(url_for('_login'))
                else:
                    abort(401)
            else:
                return view_func(*args, **kwargs)
        return wrapper

    def owner_required(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            owner = None
            if 'owner' in session:
                uid = session['owner']
                owner = getResourceOwner(uid)
            elif request.authorization:
                username = request.authorization.username
                owner = getResourceOwner(username)
                if not owner or not owner.check_password(request.authorization.password):
                    abort(401)
            g.owner = owner
            if not owner:
                if "Accept" in request.headers and "text/html" in request.headers.get("Accept"):
                    session["owner"] = True
                    session["redirect"] = request.url
                    return redirect(url_for('_login'))
                else:
                    abort(401)
            else:
                return view_func(*args, **kwargs)
        return wrapper

    # Custom function to serve CSS and Javascript files
    @route(AUTH_VERSION_ROOT + 'static/<filename>', auto_json=False)
    def style(self, filename):
        return send_from_directory(SCRIPT_DIR + '/static', filename)

    @route('/')
    def index(self):
        return (200, [APINAMESPACE + "/"])

    @route('/' + APINAMESPACE + "/")
    def namespaceindex(self):
        return (200, [APINAME + "/"])

    @route(AUTH_API_ROOT + '/')
    def nameindex(self):
        return (200, [APIVERSION + "/"])

    @route(AUTH_VERSION_ROOT)
    def versionindex(self):
        obj = ["register_client/", "revoke/", "authorize/", "token/", "certs/"]
        return (200, obj)

    @route(AUTH_VERSION_ROOT + 'test/', auto_json=True)
    @RequiresAuth(condition=True)
    def test(self):
        return (200, "Hello World")

    @route(AUTH_VERSION_ROOT + 'login/', methods=['GET', 'POST'], auto_json=False)
    def login(self):
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            if not username or not password:
                message = "Please Fill In Both Username and Password."
                return render_template('login.html', message=message)
            if "owner" in session and session["owner"] is True:
                user = getResourceOwner(username)
            else:
                user = getAdminUser(username)
            if not user:
                message = "That username is not recognised. Please signup."
                return render_template('login.html', message=message)
            if user.check_password(password):
                if isinstance(user, ResourceOwner):
                    session["owner"] = user.id
                else:
                    session['id'] = user.id
                if "redirect" in session:
                    return redirect(session['redirect'])
                else:
                    return redirect(url_for('_home'))
            else:
                message = "Invalid Password. Try Again."
                return render_template('login.html', message=message)
        return render_template('login.html')

    @route(AUTH_VERSION_ROOT + 'home/', methods=['GET'], auto_json=False)
    @admin_required
    def home(self):
        user = g.user
        if user:
            clients = OAuth2Client.query.filter_by(user_id=user.id).all()
        else:
            clients = []
        return render_template('home.html', user=user, clients=clients)

    @route(AUTH_VERSION_ROOT + 'signup', methods=['POST'], auto_json=False)
    def signup_post(self):
        username = request.form.get('username', None)
        password = request.form.get('password', None)
        if not username or not password:
            return redirect(url_for('_signup_get'))
        user = addAdminUser(username, password)
        if user is None:
            return render_template('signup.html', message="Invalid Username. Please choose another one.")
        # Create Resource Owner account for Admin with full Write privileges
        addResourceOwner(user, username=username, password=password, is04_access="write", is05_access="write")
        session['id'] = user.id
        return redirect(url_for('_home'))

    @route(AUTH_VERSION_ROOT + 'signup/', methods=['GET'], auto_json=False)
    def signup_get(self):
        return render_template('signup.html')

    @route(AUTH_VERSION_ROOT + 'register_client', methods=['POST'], auto_json=False)
    @admin_required
    def create_client_post(self):
        user = g.user
        if "application/json" in request.headers["Content-Type"]:
            client = OAuth2Client(**request.get_json())
        elif "application/x-www-form-urlencoded" in request.headers["Content-Type"]:
            client = OAuth2Client(**request.form.to_dict(flat=True))
        else:
            raise InvalidRequestError
        client.user_id = user.id
        client.client_id = gen_salt(24)
        if client.token_endpoint_auth_method == 'none':
            client.client_secret = ''
        else:
            client.client_secret = gen_salt(48)
        db.session.add(client)
        db.session.commit()
        if 'id' in session:
            return redirect(url_for('_home'))
        else:
            client_info = client.client_info.copy()
            client_info.update(client.client_metadata)
            return jsonify(client_info), 201

    @route(AUTH_VERSION_ROOT + 'register_client/', methods=['GET'], auto_json=False)
    @admin_required
    def create_client_get(self):
        return render_template('create_client.html')

    @route(AUTH_VERSION_ROOT + 'delete_client/<client_id>', auto_json=False)
    @admin_required
    def delete_client(self, client_id):
        removeClient(client_id)
        return redirect(url_for('_home'))

    @route(AUTH_VERSION_ROOT + 'fetch_token/', auto_json=False)
    @admin_required
    def fetch_token(self):
        user = g.user
        # TODO - drop-down select box
        client = OAuth2Client.query.filter_by(user_id=user.id).first()
        return render_template('fetch_token.html', client=client)

    @route(AUTH_VERSION_ROOT + 'authorize', methods=['POST'], auto_json=False)
    @owner_required
    def authorization_post(self):
        owner = g.owner
        if "confirm" in request.form.keys() and request.form['confirm'] == "true":
            grant_user = owner
        else:
            grant_user = None
        return authorization.create_authorization_response(grant_user=grant_user)

    @route(AUTH_VERSION_ROOT + 'authorize/', methods=['GET'], auto_json=False)
    @owner_required
    def authorization_get(self):
        owner = g.owner
        try:
            grant = authorization.validate_consent_request(end_user=owner, request=request)
        except OAuth2Error as error:
            return error.error
        return render_template('authorize.html', user=owner, grant=grant)

    @route(AUTH_VERSION_ROOT + 'token', methods=['POST'], auto_json=False)
    def issue_token_post(self):
        return authorization.create_token_response()

    @route(AUTH_VERSION_ROOT + 'revoke', methods=['POST'], auto_json=False)
    def revoke_token_post(self):
        return authorization.create_endpoint_response('revocation')

    @route(AUTH_VERSION_ROOT + 'users', methods=['GET', 'POST'], auto_json=False)
    @admin_required
    def get_users(self):
        user = getAdminUser(session['id'])
        resource_owners = ResourceOwner.query.filter_by(user_id=user.id).all()
        return render_template('users.html', user=user, owners=resource_owners)

    @route(AUTH_VERSION_ROOT + 'add_user', methods=['POST'], auto_json=False)
    @admin_required
    def add_user(self):
        user = getAdminUser(session['id'])
        username = request.form.get("username")
        password = request.form.get("password")
        is04 = request.form.get("is04")
        is05 = request.form.get("is05")
        if any(i in [None, ''] for i in (user, username, password)):
            return redirect(url_for('_get_users'))
        else:
            addResourceOwner(user, username, password, is04, is05)
        return redirect(url_for('_get_users'))

    @route(AUTH_VERSION_ROOT + 'users/<username>', methods=['GET'], auto_json=False)
    @admin_required
    def delete_user(self, username):
        removeResourceOwner(username)
        return redirect(url_for('_get_users'))

    # route for certificate with public key
    @route(AUTH_VERSION_ROOT + 'certs/', methods=['GET'], auto_json=True)
    def get_cert(self):
        try:
            with open(CERT_PATH, 'r') as myfile:
                cert = myfile.read()
            return (200, [cert])
        except OSError as e:
            self.logger.writeError("Error: {}\nFile at {} doesn't exist".format(e, CERT_PATH))
            raise

    @route(AUTH_VERSION_ROOT + 'logout/', auto_json=False)
    def logout(self):
        try:
            del session['id']
            del session['redirect']
        except Exception as e:
            self.logger.writeDebug("Error: {}. Couldn't delete session ID or Redirect string".format(str(e)))
        return redirect(url_for('_login'))
