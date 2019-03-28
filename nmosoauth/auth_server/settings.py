import os
from datetime import timedelta
from .constants import NMOSOAUTH_DIR, PRIVKEY_FILE, DATABASE_NAME

pkg = ''
if __package__ is not None:
    pkg = __package__ + '.'


class BaseConfig(object):
    DEBUG = True
    TESTING = False
    SECRET_KEY = 'secret'
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=5)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///{}/{}.sqlite'.format(NMOSOAUTH_DIR, DATABASE_NAME)
    BASIC_AUTH_REALM = "NMOS Auth Server Login Required"
    OAUTH2_ACCESS_TOKEN_GENERATOR = pkg + 'token_generator.gen_token'
    OAUTH2_REFRESH_TOKEN_GENERATOR = True
    OAUTH2_JWT_ENABLED = True
    OAUTH2_JWT_ISS = 'http://rd.bbc.co.uk/x-nmos/auth/v1.0/'
    OAUTH2_JWT_ALG = 'RS256'
    OAUTH2_JWT_EXP = 60
    OAUTH2_JWT_KEY_PATH = os.path.join(NMOSOAUTH_DIR, PRIVKEY_FILE)


class TestConfig(BaseConfig):
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    OAUTH2_JWT_KEY_PATH = None


class ProductionConfig(BaseConfig):
    DEBUG = False
