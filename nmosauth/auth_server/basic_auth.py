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

from functools import wraps
from flask import Response, request, current_app, render_template

from .models import AdminUser


class BasicAuthorization():
    """
    A Flask extension for adding HTTP basic access authentication to the
    application.
    """

    def __init__(self, app=None):
        if app is not None:
            self.app = app
            self.init_app(app)
        else:
            self.app = None

    def init_app(self, app):
        self.app = app
        app.config.setdefault('BASIC_AUTH_REALM', '')
        app.config.setdefault('BASIC_AUTH_FORCE', False)

        @app.before_request
        def require_basic_auth():
            if not current_app.config['BASIC_AUTH_FORCE']:
                return
            if not self.authenticate():
                return self.challenge()

    def check_credentials(self, username, password):
        try:
            user = AdminUser.query.filter_by(username=username).first()
            return username == user.username and password == user.password
        except Exception:
            return False

    def authenticate(self):
        auth = request.authorization
        return (
            auth and auth.type == 'basic' and self.check_credentials(auth.username, auth.password)
        )

    def challenge(self):
        realm = current_app.config['BASIC_AUTH_REALM']
        return Response(
            status=401,
            headers={'WWW-Authenticate': 'Basic realm="{}"'.format(realm)},
            response=render_template('error.html', code=401, message="Unauthorised")
        )

    def required(self, view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            if self.authenticate():
                return view_func(*args, **kwargs)
            else:
                return self.challenge()
        return wrapper


basicAuth = BasicAuthorization()
