from datetime import datetime
from functools import wraps
from flask import Flask, jsonify, request, current_app
from flask_jwt_simple import (
    JWTManager, jwt_required, create_jwt, get_jwt, get_jwt_identity
)
from flask_jwt_simple.view_decorators import _decode_jwt_from_headers
from nmoscommon.webapi import *
try:
    from flask import _app_ctx_stack as ctx_stack
except ImportError:  # pragma: no cover
    from flask import _request_ctx_stack as ctx_stack

web_api = WebAPI()
app = web_api.app

app.config['JWT_ACCESS_TOKEN_EXPIRES'] = False
app.config['JWT_IDENTITY_CLAIM'] = 'role'
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

@jwt.jwt_data_loader
def add_claims_to_access_token(identity):
    now = datetime.utcnow()
    return {
        'exp': now + current_app.config['JWT_EXPIRES'],
        'iat': now,
        'nbf': now,
        'role': identity
    }


# Provide a method to create access tokens. The create_jwt()
# function is used to actually generate the token
@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    params = request.get_json()
    username = params.get('username', None)
    password = params.get('password', None)
    role = params.get('role', None)

    if not username:
        return jsonify({"msg": "Missing username parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400
    if not role:
        return jsonify({"msg": "Missing role parameter"}), 400

    # Identity can be any data that is json serializable
    ret = {'jwt': create_jwt(identity=role)}
    return jsonify(ret), 200


def role_required(roles):
    def role_decorator(func):
        @wraps(func)
        @jwt_required
        def wrapper(*args, **kwargs):
            print "start"
            jwt_data = get_jwt()
            if jwt_data['role'] in roles:
                return func(*args, **kwargs)
            return (400, jsonify({"msg": "Please Do One!"}))
        return wrapper
    return role_decorator


@app.route('/protected', methods=['GET'])
@role_required(['dev', 'admin'])
def protected():
    print get_jwt()
    # Access the identity of the current user with get_jwt_identity
    return jsonify({'hello_from': get_jwt_identity()}), 200

if __name__ == '__main__':
    app.run()
