from flask import Blueprint, request, session
from flask import render_template, redirect, jsonify
import requests
from requests.auth import HTTPBasicAuth
from werkzeug.security import gen_salt
from authlib.flask.oauth2 import current_token
from authlib.specs.rfc6749 import OAuth2Error
from models import db, User, OAuth2Client
from oauth2 import authorization, require_oauth

bp = Blueprint(__name__, 'home')


def current_user():
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)
    return None


@bp.route('/index')
def index():
    user = current_user()
    if not user:
        return redirect('/')
    # TODO - specific client
    client = OAuth2Client.query.filter_by(user_id=user.id).first()
    return render_template('index.html', client=client)


@bp.route('/', methods=('GET', 'POST'))
def home():
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username)
            db.session.add(user)
            db.session.commit()
            # return render_template("404.html")
        session['id'] = user.id
        return redirect('/')
    user = current_user()
    if user:
        clients = OAuth2Client.query.filter_by(user_id=user.id).all()
    else:
        clients = []
    return render_template('home.html', user=user, clients=clients)


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
                'http://127.0.0.1:5000/oauth/token',
                auth=HTTPBasicAuth(client_id, client_secret),
                headers=headers,
                data=data).json()
        # print resp
        if 'access_token' in resp.keys():
            session['token'] = resp['access_token']
    if 'token' in session.keys():
        pass
    else:
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
    return '''
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugd
UWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQs
HUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5D
o2kQ+X5xK9cipRgEKwIDAQAB
-----END PUBLIC KEY-----
'''


@bp.route('/api/me')
@require_oauth('profile')
def api_me():
    user = current_token.user
    return jsonify(id=user.id, username=user.username)
