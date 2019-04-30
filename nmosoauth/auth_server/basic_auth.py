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

from flask_basicauth import BasicAuth
from .models import User
from flask import Response, current_app, render_template


class BasicAuthorization(BasicAuth):

    def check_credentials(self, username, password):
        try:
            user = User.query.filter_by(username=username).first()
            return username == user.username and password == user.password
        except Exception:
            return False

    def challenge(self):
        realm = current_app.config['BASIC_AUTH_REALM']
        return Response(
            status=401,
            headers={'WWW-Authenticate': 'Basic realm="{}"'.format(realm)},
            response=render_template('error.html', code=401, message="Unauthorised")
        )


basicAuth = BasicAuthorization()
