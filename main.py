from functools import wraps
from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token, verify_jwt_in_request,
    get_jwt_identity, get_jwt_claims
)
from nmoscommon.webapi import *

#app = Flask(__name__)

web_api = WebAPI()
app = web_api.app

# Setup the Flask-JWT-Extended extension
#app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this!
app.config['JWT_ALGORITHM'] = 'RS256'
app.config['JWT_PRIVATE_KEY'] = '''
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw
33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW
+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB
AoGAD+onAtVye4ic7VR7V50DF9bOnwRwNXrARcDhq9LWNRrRGElESYYTQ6EbatXS
3MCyjjX2eMhu/aF5YhXBwkppwxg+EOmXeh+MzL7Zh284OuPbkglAaGhV9bb6/5Cp
uGb1esyPbYW+Ty2PC0GSZfIXkXs76jXAu9TOBvD0ybc2YlkCQQDywg2R/7t3Q2OE
2+yo382CLJdrlSLVROWKwb4tb2PjhY4XAwV8d1vy0RenxTB+K5Mu57uVSTHtrMK0
GAtFr833AkEA6avx20OHo61Yela/4k5kQDtjEf1N0LfI+BcWZtxsS3jDM3i1Hp0K
Su5rsCPb8acJo5RO26gGVrfAsDcIXKC+bQJAZZ2XIpsitLyPpuiMOvBbzPavd4gY
6Z8KWrfYzJoI/Q9FuBo6rKwl4BFoToD7WIUS+hpkagwWiz+6zLoX1dbOZwJACmH5
fSSjAkLRi54PKJ8TFUeOP15h9sQzydI8zJU+upvDEKZsZc/UhT/SySDOxQ4G/523
Y0sz/OZtSWcol/UMgQJALesy++GdvoIDLfJX5GBQpuFgFenRiRDabxrE9MNUZ2aP
FaFp+DyAe+b4nDwuJaW2LURbr8AEZga7oQj0uYxcYw==
-----END RSA PRIVATE KEY-----
'''
app.config['JWT_PUBLIC_KEY'] = '''
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugd
UWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQs
HUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5D
o2kQ+X5xK9cipRgEKwIDAQAB
-----END PUBLIC KEY-----
'''
jwt = JWTManager(app)

class UserObject:
    def __init__(self, username, roles):
        self.username = username
        self.roles = roles

@jwt.user_claims_loader
def add_claims_to_access_token(user):
    return {'roles': user.roles}

@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.username

# @jwt.claims_verification_loader
# def verify_claims(custom_claims):
#     print custom_claims
#     if custom_claims['roles'] == 'dev':
#         return True
#     else:
#         return False

# @jwt.claims_verification_failed_loader
# def claims_failed():
#     return jsonify({"msg": "Please Do One!"}), 400

# Provide a method to create access tokens. The create_access_token()
# function is used to actually generate the token, and you can return
# it to the caller however you choose.
@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)
    role = request.json.get('role', None)

    user = UserObject(username, role)

    if not username:
        return jsonify({"msg": "Missing username parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400
    if not role:
        return jsonify({"msg": "Missing role parameter"}), 400

    # Identity can be any data that is json serializable
    access_token = create_access_token(identity=user)
    return jsonify({"access_token": access_token}), 200

# Protect a view with jwt_required, which requires a valid access token
# in the request to access.
@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    print current_user
    current_claims = get_jwt_claims()
    print current_claims

    return jsonify(logged_in_as=current_user), 200

def role_required(roles):
    def role_decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            print "start"
            verify_jwt_in_request()
            claims = get_jwt_claims()
            print claims
            if claims['roles'] in roles:
                print "finish"
                return func(*args, **kwargs)
            return jsonify({"msg": "Please Do One!"}), 400
        return wrapper
    return role_decorator

@app.route('/protected2', methods=['GET'])
@role_required(['dev', 'admin'])
def protected2():
    current_user = get_jwt_identity()
    return jsonify({"logged_in_as": current_user}), 200


if __name__ == '__main__':
    app.run()
