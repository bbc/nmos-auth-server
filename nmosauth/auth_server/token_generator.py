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
from authlib.specs.rfc7519 import jwt
import datetime
from .oauth2 import authorization
from .models import AccessRights
from .constants import NMOSAUTH_DIR


class TokenGenerator():

    def __init__(self):
        pass

    def get_access_rights(self, user, scope):
        if scope == "is04":
            user_access = AccessRights.query.filter_by(user_id=user.id).first()
            access = user_access.is04
        elif scope == "is05":
            user_access = AccessRights.query.filter_by(user_id=user.id).first()
            access = user_access.is05
        else:
            access = None
        return access

    def get_audience(self, user, scope, access):
        if access is None:
            return None
        if scope == "is04":
            if access == "write":
                audience = "IS-04 Write Access".split(" ")
            if access == "read":
                audience = "IS-04 Read Access".split(" ")
        elif scope == "is05":
            if access == "write":
                audience = "IS-05 Write Access".split(" ")
            if access == "read":
                audience = "IS-04 Read Access".split(" ")
        else:
            audience = None
        return audience

    def get_scope(self, user, client, scope):

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
        audience = self.get_audience(user, scope, access)
        new_scope = self.get_scope(user, client, scope)

        header = {
            "alg": config["jwt_alg"],
            "typ": "JWT"
        }
        payload = {
            'iat': current_time,
            'exp': current_time + datetime.timedelta(seconds=config['jwt_exp']),
            'nbf': current_time,
            'iss': config['jwt_iss'],
            'sub': user.username,
            'scope': new_scope,
            'aud': audience,
            'x-nmos-api': {'name': new_scope,
                           'access': access}
        }

        try:
            key = config['jwt_key']
        except Exception as e:
            print("Error: " + e)
            abs_key_path = os.path.join(NMOSAUTH_DIR, "privkey.pem")
            with open(abs_key_path, 'r') as myfile:
                key = myfile.read()

        return jwt.encode(
            header,
            payload,
            key
        )


# Needed for access_token path in Flask config
gen_token = TokenGenerator().gen_access_token
