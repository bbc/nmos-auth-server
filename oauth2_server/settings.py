import os

CWD = os.path.dirname(__file__)


class BaseConfig(object):
    DEBUG = True
    TESTING = False
    PORT = 4999
    SECRET_KEY = 'secret'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///{}/db.sqlite'.format(CWD)
    OAUTH2_ACCESS_TOKEN_GENERATOR = 'token_generator.gen_token'
    OAUTH2_REFRESH_TOKEN_GENERATOR = True
    OAUTH2_JWT_ENABLED = True
    OAUTH2_JWT_ISS = 'https://oauth.rd.bbc.co.uk'
    OAUTH2_JWT_ALG = 'RS256'
    OAUTH2_JWT_EXP = 30
    OAUTH2_JWT_KEY_PATH = 'certs/key.pem'


class TestConfig(BaseConfig):
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///dbtest.sqlite'
