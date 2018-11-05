import os
from flask import Blueprint, request, session
from flask import render_template, redirect, jsonify
import requests
from requests.auth import HTTPBasicAuth
from werkzeug.security import gen_salt
from authlib.specs.rfc6749 import OAuth2Error
from models import db, User, OAuth2Client, AccessRights
from oauth2 import authorization
from authlib.common.errors import AuthlibHTTPError

bp = Blueprint(__name__, 'home')


def current_user():
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)
    return None


@bp.errorhandler(AuthlibHTTPError)
def error_handler(error):
    e = error()
    status = e[0]
    body = e[1]
    headers = e[2]
    print error.message
    return (jsonify(body), status, headers)


@bp.route('/fetch_token')
def fetch_token():
    user = current_user()
    if not user:
        return redirect('/')
    # TODO - specific client
    client = OAuth2Client.query.filter_by(user_id=user.id).first()
    return render_template('fetch_token.html', client=client)


@bp.route('/', methods=('GET', 'POST'))
def home():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        print username, password
        if not username or not password:
            message = "Please Fill In Both Username and Password."
            return render_template('home.html', user=None, clients=None, message=message)
        user = User.query.filter_by(username=username).first()
        if not user:
            message = "That username is not recognised. Please signup."
            return render_template('home.html', user=None, clients=None, message=message)
        if user.password == password:
            session['id'] = user.id
            return redirect('/')
        else:
            message = "Invalid Password. Try Again."
            return render_template('home.html', user=None, clients=None, message=message)
    user = current_user()
    if user:
        clients = OAuth2Client.query.filter_by(user_id=user.id).all()
    else:
        clients = []
    return render_template('home.html', user=user, clients=clients, message="")


@bp.route('/signup', methods=('GET', 'POST'))
def signup():
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
        return redirect('/')


@bp.route('/logout')
def logout():
    del session['id']
    return redirect('/')


@bp.route('/create_client', methods=('GET', 'POST'))
def create_client():
    user = current_user()
    if not user:
        return redirect('/')
    if request.method == 'GET':
        return render_template('create_client.html')
    client = OAuth2Client(**request.form.to_dict(flat=True))
    client.user_id = user.id
    client.client_id = gen_salt(24)
    if client.token_endpoint_auth_method == 'none':
        client.client_secret = ''
    else:
        client.client_secret = gen_salt(48)
    db.session.add(client)
    db.session.commit()
    return redirect('/')


@bp.route('/request_token', methods=['GET', 'POST'])
def request_token():
    user = current_user()
    if not user:
        return redirect('/')
    # TODO - specific client
    client = OAuth2Client.query.filter_by(user_id=user.id).first()
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        scope = request.form.get('scope')
        grant_type = 'password'
        client_id = client.client_id
        client_secret = client.client_secret
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = {'scope': scope, 'grant_type': grant_type,
                'username': username, 'password': password}
        resp = requests.post(
                request.url_root + 'oauth/token',
                auth=HTTPBasicAuth(client_id, client_secret),
                headers=headers,
                data=data).json()
        if 'access_token' in resp.keys():
            session['token'] = resp['access_token']
    if 'token' not in session.keys():
        session['token'] = None
    return render_template('request.html', user=user,
                           client=client, token=session['token'])


@bp.route('/oauth/authorize', methods=['GET', 'POST'])
def authorize():
    user = current_user()
    if request.method == 'GET':
        try:
            grant = authorization.validate_consent_request(end_user=user)
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


@bp.route('/oauth/token', methods=['POST'])
def issue_token():
    return authorization.create_token_response()


@bp.route('/oauth/revoke', methods=['POST'])
def revoke_token():
    return authorization.create_endpoint_response('revocation')


# route for certificate with public key
@bp.route('/certs', methods=['GET'])
def get_cert():
    SCRIPT_DIR = os.path.dirname(__file__)
    abs_pubkey_path = os.path.join(SCRIPT_DIR, "certs", "certificate.pem")
    try:
        with open(abs_pubkey_path, 'r') as myfile:
            pubkey = myfile.read()
        return pubkey
    except OSError as e:
        print("Error: " + e + "\nFile at " + abs_pubkey_path + "doesn't exist")
        raise
