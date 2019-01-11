import os

SCRIPT_DIR = os.path.dirname(__file__)
FILE_DIR = '/var/nmosoauth'

pkg = ''
if __package__ is not None:
    pkg = __package__ + '.'


class BaseConfig(object):
    DEBUG = True
    TESTING = False
    SECRET_KEY = 'secret'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = 'sqlite://{}/db.sqlite'.format(FILE_DIR)
    OAUTH2_ACCESS_TOKEN_GENERATOR = pkg + 'token_generator.gen_token'
    OAUTH2_REFRESH_TOKEN_GENERATOR = True
    OAUTH2_JWT_ENABLED = True
    OAUTH2_JWT_ISS = 'https://oauth.rd.bbc.co.uk'
    OAUTH2_JWT_ALG = 'RS256'
    OAUTH2_JWT_EXP = 30
    OAUTH2_JWT_KEY_PATH = FILE_DIR + '/privkey.pem'
    # OAUTH2_JWT_KEY_PATH = SCRIPT_DIR + '/certs/privkey.pem'


class TestConfig(BaseConfig):
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite://{}/dbtest.sqlite'.format(FILE_DIR)
