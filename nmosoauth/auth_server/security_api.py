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
from flask import request, session, send_from_directory
from flask import render_template, redirect, url_for, jsonify
from werkzeug.security import gen_salt
from jinja2 import FileSystemLoader, ChoiceLoader
from authlib.specs.rfc6749 import OAuth2Error
from nmoscommon.webapi import WebAPI, route
from nmoscommon.auth.nmos_auth import RequiresAuth

from .models import db, User, OAuth2Client
from .oauth2 import authorization
from .app import config_app
from .basic_auth import basicAuth
from .db_utils import getUser, removeClient, addUser, addAccessRights
from .constants import CERT_PATH, CERT_KEY

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

    def current_user(self):
        if 'id' in session:
            uid = session['id']
            return User.query.get(uid)
        return None

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
        obj = ["home/", "signup/", "register_client/", "fetch_token/", "revoke/", "authorize/", "token/", "certs/"]
        return (200, obj)

    @route(AUTH_VERSION_ROOT + 'test/', auto_json=True)
    @RequiresAuth()
    def test(self):
        return (200, "Hello World")

    @route(AUTH_VERSION_ROOT + 'home/', methods=['GET', 'POST'], auto_json=False)
    def home(self):
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            if not username or not password:
                message = "Please Fill In Both Username and Password."
                return render_template('home.html', user=None, clients=None, message=message)
            user = User.query.filter_by(username=username).first()
            if not user:
                message = "That username is not recognised. Please signup."
                return render_template('home.html', user=None, clients=None, message=message)
            if user.password == password:
                session['id'] = user.id
                return redirect(url_for('_home'))
            else:
                message = "Invalid Password. Try Again."
                return render_template('home.html', user=None, clients=None, message=message)
        user = self.current_user()
        if user:
            clients = OAuth2Client.query.filter_by(user_id=user.id).all()
        else:
            clients = []
        return render_template('home.html', user=user, clients=clients, message="")

    @route(AUTH_VERSION_ROOT + 'signup', methods=['POST'], auto_json=False)
    def signup_post(self):
        username = request.form.get('username', None)
        password = request.form.get('password', None)
        if not username or not password:
            return redirect(url_for('_signup_get'))
        user = addUser(username, password)

        is04 = request.form.get('is04', None)
        is05 = request.form.get('is05', None)
        addAccessRights(user, is04, is05)

        session['id'] = user.id
        return redirect(url_for('_home'))

    @route(AUTH_VERSION_ROOT + 'signup/', methods=['GET'], auto_json=False)
    def signup_get(self):
        return render_template('signup.html')

    @route(AUTH_VERSION_ROOT + 'register_client', methods=['POST'], auto_json=False)
    @basicAuth.required
    def create_client_post(self):
        user = self.current_user()
        if not user and request.authorization:
            user = getUser(request.authorization.username)
        client = OAuth2Client(**request.form.to_dict(flat=True))
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
    def create_client_get(self):
        user = self.current_user()
        if not user:
            return redirect(url_for('_home'))
        return render_template('create_client.html')

    @route(AUTH_VERSION_ROOT + 'delete_client/<client_id>', auto_json=False)
    def delete_client(self, client_id):
        removeClient(client_id)
        return redirect(url_for('_home'))

    @route(AUTH_VERSION_ROOT + 'fetch_token/', auto_json=False)
    def fetch_token(self):
        user = self.current_user()
        if not user:
            return redirect(url_for('_home'))
        # TODO - drop-down select box
        client = OAuth2Client.query.filter_by(user_id=user.id).first()
        return render_template('fetch_token.html', client=client)

    @route(AUTH_VERSION_ROOT + 'authorize', methods=['POST'], auto_json=False)
    def authorization_post(self):
        user = self.current_user()
        if not user and request.authorization:
            user = getUser(request.authorization.username)
        if not user and 'username' in request.form:
            username = request.form.get('username')
            user = User.query.filter_by(username=username).first()
        if request.form['confirm']:
            grant_user = user
        else:
            grant_user = None
        return authorization.create_authorization_response(grant_user=grant_user)

    @route(AUTH_VERSION_ROOT + 'authorize/', methods=['GET'], auto_json=False)
    def authorization_get(self):
        user = self.current_user()
        if not user and request.authorization:
            user = getUser(request.authorization.username)
        try:
            grant = authorization.validate_consent_request(end_user=user, request=request)
        except OAuth2Error as error:
            return error.error
        return render_template('authorize.html', user=user, grant=grant)

    @route(AUTH_VERSION_ROOT + 'token', methods=['POST'], auto_json=False)
    def issue_token_post(self):
        return authorization.create_token_response()

    @route(AUTH_VERSION_ROOT + 'revoke', methods=['POST'], auto_json=False)
    def revoke_token_post(self):
        return authorization.create_endpoint_response('revocation')

    # route for certificate with public key
    @route(AUTH_VERSION_ROOT + 'certs/', methods=['GET'], auto_json=True)
    def get_cert(self):
        try:
            with open(CERT_PATH, 'r') as myfile:
                cert = myfile.read()
            return (200, {CERT_KEY: cert})
        except OSError as e:
            self.logger.writeError("Error: {}\nFile at {} doesn't exist".format(e, CERT_PATH))
            raise

    @route(AUTH_VERSION_ROOT + 'logout/', auto_json=False)
    def logout(self):
        try:
            del session['id']
        except Exception as e:
            self.logger.writeDebug("Error: {}. Couldn't delete session ID".format(str(e)))
        return redirect(url_for('_home'))
