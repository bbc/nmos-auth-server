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
