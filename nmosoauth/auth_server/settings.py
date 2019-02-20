import os
from ..constants import NMOSOAUTH_DIR, PRIVKEY_FILE, DATABASE_NAME, TEST_PRIV_KEY

pkg = ''
if __package__ is not None:
    pkg = __package__ + '.'


class BaseConfig(object):
    DEBUG = True
    TESTING = False
    SECRET_KEY = 'secret'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///{}/{}.sqlite'.format(NMOSOAUTH_DIR, DATABASE_NAME)
    BASIC_AUTH_FORCE = True
    OAUTH2_ACCESS_TOKEN_GENERATOR = pkg + 'token_generator.gen_token'
    OAUTH2_REFRESH_TOKEN_GENERATOR = True
    OAUTH2_JWT_ENABLED = True
    OAUTH2_JWT_ISS = 'https://oauth.rd.bbc.co.uk'
    OAUTH2_JWT_ALG = 'RS256'
    OAUTH2_JWT_EXP = 31557600
    OAUTH2_JWT_KEY_PATH = os.path.join(NMOSOAUTH_DIR, PRIVKEY_FILE)



class TestConfig(BaseConfig):
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    OAUTH2_JWT_KEY_PATH = None
    OAUTH2_JWT_KEY = TEST_PRIV_KEY
