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
from werkzeug.security import check_password_hash
from authlib.integrations.sqla_oauth2 import (
    OAuth2ClientMixin,
    OAuth2AuthorizationCodeMixin,
    OAuth2TokenMixin,
)


__all__ = ['db', 'AdminUser', 'OAuth2Client',
           'OAuth2AuthorizationCode', 'OAuth2Token', 'ResourceOwner']

db = SQLAlchemy()


class AdminUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True)
    password = db.Column(db.String(20))

    def __str__(self):
        output = {}
        for c in self.__table__.columns:
            output[c.name] = getattr(self, c.name)
        return str(output)

    def get_user_id(self):
        return self.id

    def check_password(self, password):
        return check_password_hash(self.password, password)


class OAuth2Client(db.Model, OAuth2ClientMixin):
    __tablename__ = 'oauth2_client'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('admin_user.id', ondelete='CASCADE'))
    admin_user = db.relationship('AdminUser')


class OAuth2AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
    __tablename__ = 'oauth2_code'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('admin_user.id', ondelete='CASCADE'))
    admin_user = db.relationship('AdminUser')
    code_challenge = db.Column(db.String(48))
    code_challenge_method = db.Column(db.String(5))


class OAuth2Token(db.Model, OAuth2TokenMixin):
    __tablename__ = 'oauth2_token'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('admin_user.id', ondelete='CASCADE'))
    admin_user = db.relationship('AdminUser')
    access_token = db.Column(db.String(255), nullable=False)

    def is_refresh_token_expired(self):
        expires_at = self.issued_at + self.expires_in * 1440
        return expires_at < time.time()


class ResourceOwner(db.Model):
    __tablename__ = 'resource_owner'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('admin_user.id', ondelete='CASCADE'))
    admin_user = db.relationship('AdminUser')

    username = db.Column(db.String(40), unique=True, nullable=False)
    password = db.Column(db.String(20))

    registration_access = db.Column(db.String(25))
    query_access = db.Column(db.String(25))
    node_access = db.Column(db.String(25))
    connection_access = db.Column(db.String(25))

    def get_user_id(self):
        return self.id

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def __str__(self):
        output = {}
        for c in self.__table__.columns:
            output[c.name] = getattr(self, c.name)
        return str(output)
