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

IS04_SCOPES = ["is04", "IS04", "is-04", "IS-04"]
IS05_SCOPES = ["is05", "IS05", "is-05", "IS-05"]


class TokenGenerator():

    def __init__(self):
        pass

    def get_access_rights(self, user, scope_list):
        if user is None:
            return "client_credentials"
        else:
            for scope in scope_list:
                if scope in IS04_SCOPES:
                    access = user.is04
                elif scope == "is-05":
                    access = user.is05
                else:
                    access = None
            return access

    def get_audience(self, scope_list):
        audience = []
        for scope in scope_list:
            if scope in IS04_SCOPES:
                audience.extend([
                    "registry",
                    "query"
                ])
            elif scope in IS05_SCOPES:
                audience.extend([
                    "senders",
                    "receivers"
                ])
        return audience

    def populate_nmos_claim(self, user, scope_list):
        nmos_claim = {}
        user_access = AccessRights.query.filter_by(user_id=user.id).first()
        if user_access:
            for scope in scope_list:
                nmos_claim[scope] = {}
                try:
                    api_access = getattr(user_access, scope.replace('-', ''))
                    nmos_claim[scope][api_access] = {"resources": "*"}
                except Exception:
                    pass
        return nmos_claim

    def gen_access_token(self, client, grant_type, user, scope):
        # Scope is space-delimited so convert to list
        scope_list = scope.split(' ')
        # Get Auth Config (set in ./settings)
        config = authorization.config
        # Current time set in `iat` and `nbf` claims
        current_time = datetime.datetime.utcnow()
        # Use username of user or `None` for when client_credentials is used
        subject = user.username if user is not None else None
        # Populate audience claim
        audience = self.get_audience(scope_list)
        # Populate NMOS claims
        x_nmos_claim = self.populate_nmos_claim(user, scope_list)

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
            'aud': audience,
            'x-nmos-api': x_nmos_claim
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
