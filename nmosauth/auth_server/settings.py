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
from datetime import timedelta
from .constants import NMOSAUTH_DIR, PRIVKEY_PATH, DATABASE_NAME

pkg = ''
if __package__ is not None:
    pkg = __package__ + '.'


class BaseConfig(object):
    DEBUG = True
    TESTING = False
    SECRET_KEY = os.urandom(16)
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=5)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///{}/{}.sqlite'.format(NMOSAUTH_DIR, DATABASE_NAME)
    BASIC_AUTH_REALM = "NMOS Auth Server Login Required"
    OAUTH2_ACCESS_TOKEN_GENERATOR = pkg + 'token_generator.gen_token'
    OAUTH2_REFRESH_TOKEN_GENERATOR = True
    OAUTH2_JWT_ENABLED = True
    OAUTH2_JWT_ISS = 'http://rd.bbc.co.uk/x-nmos/auth/v1.0/'
    OAUTH2_JWT_ALG = 'RS256'
    OAUTH2_JWT_EXP = 60
    OAUTH2_JWT_KEY_PATH = PRIVKEY_PATH


class TestConfig(BaseConfig):
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    OAUTH2_JWT_KEY_PATH = None


class ProductionConfig(BaseConfig):
    DEBUG = False
