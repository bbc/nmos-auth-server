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

import time
from flask_sqlalchemy import SQLAlchemy
from authlib.flask.oauth2.sqla import (
    OAuth2ClientMixin,
    OAuth2AuthorizationCodeMixin,
    OAuth2TokenMixin,
)
from authlib.specs.rfc6749.errors import OAuth2Error

__all__ = ['db', 'User', 'OAuth2Client',
           'OAuth2AuthorizationCode', 'OAuth2Token', 'AccessRights']

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True)
    password = db.Column(db.String(20))

    def __str__(self):
        output = ''
        for c in self.__table__.columns:
            output += '{}: {},  '.format(c.name, getattr(self, c.name))
        return output

    def get_user_id(self):
        return self.id

    def check_password(self, password):
        return password == self.password


class OAuth2Client(db.Model, OAuth2ClientMixin):
    __tablename__ = 'oauth2_client'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')

    def check_requested_scopes(self, scopes):  # Just for testing purposes
        if len(set(scopes)) != 1:
            raise OAuth2Error("Must list a single scope", None, 400)
        return super(OAuth2Client, self).check_requested_scopes(scopes)


class OAuth2AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
    __tablename__ = 'oauth2_code'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')


class OAuth2Token(db.Model, OAuth2TokenMixin):
    __tablename__ = 'oauth2_token'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')

    def is_refresh_token_expired(self):
        expires_at = self.issued_at + self.expires_in * 2
        return expires_at < time.time()


class AccessRights(db.Model):
    __tablename__ = 'access_rights'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')
    is04 = db.Column(db.String(25))
    is05 = db.Column(db.String(25))

    def __str__(self):
        output = ''
        for c in self.__table__.columns:
            output += '{}: {},  '.format(c.name, getattr(self, c.name))
        return output
