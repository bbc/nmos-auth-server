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
from authlib.jose import jwt
import datetime
from .oauth2 import authorization
from .constants import NMOSAUTH_DIR, PRIVKEY_FILE


class TokenGenerator():

    def __init__(self):
        pass

    def get_access_rights(self, user, scope):
        if user is None:
            return "client_credentials"
        else:
            if scope == "is-04":
                access = user.is04
            elif scope == "is-05":
                access = user.is05
            else:
                access = None
            return access

    def get_audience(self, scope, access):
        audience = []
        if access is not None:
            if scope == "is-04":
                audience = [
                    "registry",
                    "query"
                ]
            elif scope == "is-05":
                audience = [
                    "senders",
                    "receivers"
                ]
        return audience

    def get_scope(self, scope):

        if scope in ["is04", "IS04", "is-04", "IS-04"]:
            new_scope = "is-04"
        elif scope in ["is05", "IS05", "is-05", "IS-05"]:
            new_scope = "is-05"
        else:
            new_scope = None
        return new_scope

    def gen_access_token(self, client, grant_type, user, scope):

        config = authorization.config
        current_time = datetime.datetime.utcnow()
        access = self.get_access_rights(user, scope)
        audience = self.get_audience(scope, access)
        subject = user.username if user is not None else None
        new_scope = self.get_scope(scope)

        header = {
            "alg": config["jwt_alg"],
            "typ": "JWT"
        }
        payload = {
            'iat': current_time,
            'exp': current_time + datetime.timedelta(seconds=config['jwt_exp']),
            'nbf': current_time,
            'iss': config['jwt_iss'],
            'sub': subject,
            'scope': new_scope,
            'aud': audience,
            'x-nmos-api': {
                'name': new_scope,
                'access': access
            }
        }

        try:
            key = config['jwt_key']
        except Exception as e:
            print("Error: " + e)
            abs_key_path = os.path.join(NMOSAUTH_DIR, PRIVKEY_FILE)
            with open(abs_key_path, 'r') as myfile:
                key = myfile.read()

        return jwt.encode(
            header,
            payload,
            key
        ).decode('utf-8')


# Needed for access_token path in Flask config
gen_token = TokenGenerator().gen_access_token
