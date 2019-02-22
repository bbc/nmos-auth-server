from flask_basicauth import BasicAuth
from .models import User
import flask
from flask import Response, current_app, abort, render_template, redirect, url_for, make_response


class BasicAuthorization(BasicAuth):

    def check_credentials(self, username, password):
        try:
            user = User.query.filter_by(username=username).first()
            return username == user.username and password == user.password
        except Exception:
            self.challenge()

    def challenge(self):
        realm = current_app.config['BASIC_AUTH_REALM']
        return Response(
            status=401,
            headers={'WWW-Authenticate': 'Basic realm="{}"'.format(realm)},
            response=render_template('404.html', code=1, message="Unauthorised")
            )


basicAuth = BasicAuthorization()
