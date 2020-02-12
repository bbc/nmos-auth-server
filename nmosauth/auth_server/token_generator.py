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
import re
import datetime
from authlib.jose import jwt

from .oauth2 import authorization
from .constants import NMOSAUTH_DIR, PRIVKEY_FILE

ALLOWED_SCOPES = ["registration", "node", "query", "connection"]


class TokenGenerator():

    def __init__(self):
        pass

    def get_audience(self, client):
        # Using Regex
        redirect_uri = client.get_default_redirect_uri()
        pattern = re.compile(r'(?:https?://)?(?:www\.)?[a-zA-Z0-9-]+((?:\.[a-zA-Z]+)+)(/?.*)')
        domain = pattern.match(redirect_uri).group(1)  # Without first subdomain, path or protocol

        # Add wildcard to beginning
        wildcard_domain = '*' + domain
        return wildcard_domain

    def populate_nmos_claim(self, user, scope_list):
        nmos_claim = {}
        if user and scope_list:
            for scope in scope_list:
                if scope not in ALLOWED_SCOPES:
                    continue
                nmos_claim[scope] = {}
                try:
                    api_access = getattr(user, scope + '_access')
                    if api_access.lower() == "write":
                        nmos_claim[scope]["write"] = ["*"]
                        nmos_claim[scope]["read"] = ["*"]
                    elif api_access.lower() == "read":
                        nmos_claim[scope]["read"] = ["*"]
                except Exception as e:
                    print(e)
        return nmos_claim

    def gen_access_token(self, client, grant_type, user, scope):
        # Scope is space-delimited so convert to list
        scope_list = scope.split()
        # Get Auth Config (set in ./settings)
        config = authorization.config
        # Current time set in `iat` and `nbf` claims
        current_time = datetime.datetime.utcnow()
        # Use username of user or client ID for when client_credentials is used
        subject = user.username if user is not None else client.client_id
        # Populate audience claim
        audience = self.get_audience(client)
        # Populate NMOS claim
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
            'client_id': client.client_id,
            'scope': (' ').join(x_nmos_claim.keys()),
            'x-nmos-api': x_nmos_claim
        }

        try:
            key = config['jwt_key']
        except Exception as e:
            print("Error: {}. Attempting to fetch private key from file".format(e))
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
