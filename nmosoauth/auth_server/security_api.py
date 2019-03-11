import os
from flask import request, session, send_from_directory
from flask import render_template, redirect, jsonify, url_for
from werkzeug.security import gen_salt
from jinja2 import FileSystemLoader, ChoiceLoader
from authlib.specs.rfc6749 import OAuth2Error
from nmoscommon.webapi import WebAPI, route

from .models import db, User, OAuth2Client, AccessRights
from .oauth2 import authorization
from .app import config_app
from .basic_auth import basicAuth
from .db_utils import getUser
from ..constants import CERT_PATH, CERT_KEY
from ..resource_server.nmos_security import NmosSecurity

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

APINAMESPACE = "x-nmos"
APINAME = "auth"
APIVERSION = "v1.0"

DEVICE_ROOT = '/{}/{}'.format(APINAMESPACE, APINAME)
VERSION_ROOT = '{}/{}/'.format(DEVICE_ROOT, APIVERSION)


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
    @route(VERSION_ROOT + 'static/<filename>', auto_json=False)
    def style(self, filename):
        return send_from_directory(SCRIPT_DIR + '/static', filename)

    @route('/')
    def __index(self):
        return (200, [APINAMESPACE + "/"])

    @route('/' + APINAMESPACE + "/")
    def __namespaceindex(self):
        return (200, [APINAME + "/"])

    @route(DEVICE_ROOT + '/')
    def __nameindex(self):
        return (200, [APIVERSION + "/"])

    @route(VERSION_ROOT)
    def __versionindex(self):
        obj = ["home/", "signup/", "register_client/", "fetch_token/", "revoke/", "authorize/", "token/", "certs/"]
        return (200, obj)

    @route(VERSION_ROOT + 'test/', auto_json=True)
    @NmosSecurity(condition=True)
    def test(self):
        return (200, "Hello World")

    @route(VERSION_ROOT + 'home/', methods=['GET', 'POST'], auto_json=False)
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

    @route(VERSION_ROOT + 'signup/', methods=['GET', 'POST'], auto_json=False)
    def signup(self):
        if request.method == 'GET':
            return render_template('signup.html')
        if request.method == 'POST':
            username = request.form.get('username', None)
            password = request.form.get('password', None)
            user = User(username=username, password=password)
            db.session.add(user)
            db.session.commit()

            is04 = request.form.get('is04', None)
            is05 = request.form.get('is05', None)
            access = AccessRights(user_id=user.id, is04=is04, is05=is05)
            db.session.add(access)
            db.session.commit()

            session['id'] = user.id
            return redirect(url_for('_home'))

    @route(VERSION_ROOT + 'register_client/', methods=['GET', 'POST'], auto_json=False)
    @basicAuth.required
    def create_client(self):
        user = self.current_user()
        if request.method == 'GET':
            return render_template('create_client.html')
        client = OAuth2Client(**request.form.to_dict(flat=True))
        if not user and request.authorization:
            user = getUser(request.authorization.username)
        client.user_id = user.id
        client.client_id = gen_salt(24)
        if client.token_endpoint_auth_method == 'none':
            client.client_secret = ''
        else:
            client.client_secret = gen_salt(48)
        db.session.add(client)
        db.session.commit()
        return redirect(url_for('_home'))

    @route(VERSION_ROOT + 'fetch_token/', auto_json=False)
    def fetch_token(self):
        user = self.current_user()
        if not user:
            return redirect(url_for('_home'))
        # TODO - specific client
        client = OAuth2Client.query.filter_by(user_id=user.id).first()
        return render_template('fetch_token.html', client=client)

    @route(VERSION_ROOT + 'authorize/', methods=['GET', 'POST'], auto_json=False)
    def authorization(self):
        user = self.current_user()
        if not user and request.authorization:
            user = getUser(request.authorization.username)
        if request.method == 'GET':
            try:
                grant = authorization.validate_consent_request(end_user=user, request=request)
            except OAuth2Error as error:
                return error.error
            return render_template('authorize.html', user=user, grant=grant)
        if not user and 'username' in request.form:
            username = request.form.get('username')
            user = User.query.filter_by(username=username).first()
        if request.form['confirm']:
            grant_user = user
        else:
            grant_user = None
        return authorization.create_authorization_response(grant_user=grant_user)

    @route(VERSION_ROOT + 'token/', methods=['POST'], auto_json=False)
    def issue_token(self):
        return authorization.create_token_response()

    @route(VERSION_ROOT + 'revoke/', methods=['POST'], auto_json=False)
    def revoke_token(self):
        return authorization.create_endpoint_response('revocation')

    # route for certificate with public key
    @route(VERSION_ROOT + 'certs/', methods=['GET'], auto_json=False)
    def get_cert(self):
        try:
            with open(CERT_PATH, 'r') as myfile:
                cert = myfile.read()
            return jsonify({CERT_KEY: cert})
        except OSError as e:
            self.logger.writeError("Error: {}\nFile at {} doesn't exist".format(e, CERT_PATH))
            raise

    @route(VERSION_ROOT + 'logout/', auto_json=False)
    def logout(self):
        try:
            del session['id']
        except Exception as e:
            self.logger.writeDebug("Error: {}. Couldn't delete session ID".format(str(e)))
        return redirect(url_for('_home'))
