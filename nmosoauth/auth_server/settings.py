import os
from ..constants import NMOSOAUTH_DIR, PRIVKEY_FILE, DATABASE_NAME

pkg = ''
if __package__ is not None:
    pkg = __package__ + '.'


class BaseConfig(object):
    DEBUG = True
    TESTING = False
    SECRET_KEY = 'secret'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///{}/{}.sqlite'.format(NMOSOAUTH_DIR, DATABASE_NAME)
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
    OAUTH2_JWT_KEY = '''
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDI+QXfWFLCkAtw
ZLg3NnaG11ZQNJsroIzoW+4scM08INartczXmBA+a/E2Pae66jmrx7ezkQ32/F0c
WJAtGK9hxuo8mFACdRDpC5QQ9Yajgca/0LWcXButTMa4uDVpKCPXLDUVrpKzKTHe
1vZSw3hwAowfJp0JQPlOK/sWwLdHIxFeu5r6fyGh8b2pZrFF9zNz80HoqepfCIYe
YQfK/RHcCJCI9VL2ZXEUFwMIo5oCsmU11A8ciN+lDi7k/rdlEzDU+N6q5iceQWyw
3ffH87I4O/DcuKI5O4IB2Zs0O+6s7bQ8zSRr26El34i/i8HdvctXxoiAxQkJzmcT
4m9ZGGdTAgMBAAECggEAeruReYc/62/6fGYWFindkpV5MbweszL2OoTB3EP7ImhP
kUeSVGuaJ/TVtzFJ+J1IIP7z0eaY56fQ2RnA2rmDiavnqp+95PJHJHscroqy8bG0
hbnY3ydlA52qkm50t8Z6tNJbjOUy09UpjpQqk/qp14XGutNi/Z6/YZz8VzXT981+
nc89PHZ0rPpWppe40j9yKpxoykV3SV0pJggxIPe/GY29xUGnhPRsOTn/qeiDyRIC
W3sLPKy+lVot/onvQ4losqT9xYtgih4ljQ0SndFVsCiqwV3wzpVCaaPIojAPY7ab
DnmQQ3W49ERBqJHzwFjjz/PIPw9p4e8FiHW1vkptYQKBgQDmsS10O6fve7OFOqEy
1U9qOqOLVCGrgxR7tnzL1snVijcCowdoAGLr3Q7dsJkHFHR5FZfQIKrzOFAEhYyM
/xIgUqxWjoS4i9UPG6sZvigdC8kXaPd9Ob3j5yacZnvPfKsUuIKF91PWaXlRtXzb
ySlwisGfHx+jLL+74JhsyIvt0QKBgQDfBTLX83pYk2ImpRy7DuYSHbHcuThJtv+1
7al7onmiE6dbDcaWmJKfOYMdqZsm5+Kf+yCxRm9x0cfY6t+Z/5uHG/dXwfRwJG2B
l8QatufWowccPgpEI2sc8apgsxlVg5Dj1dp5Uwu4RrZFl49kdP5agFEseTS22fzY
ehG6PCrX4wKBgBCX6fcUW24EbdNFdlbbtQylDyJ0eL+HfC+x3qQi3P25JV/RLjUy
4eqpSep0S22Q8RfMj9DuqJ06Dbdli8iQiFM+3xqSwcUsebTOfq4pWWVNdbdzW2ns
f1YnSEWzsXApPX0OEIVmVudzSsCv1z1P6OUpdefmKzZnf5sZ+pzIiBghAoGATu6N
FydCRvUqyNipOX9FaGYAHEmlpVlSWXZbBLn1aKqiEbTnc0depWH6iNYNZpCtgcek
w3lVWihQHfLK3rs7tW7tdK7dr48E/tfS/U188ldS3ekLQyBx+ZWCoqTgs4ZUEn8O
yt/chwTn3+uLQZeyqh8+G4puYMT4Gzng6lP/KdcCgYEA5D6xHiAEP2yFwCR5tn+0
HSyw7u3pQAa5/w+/+98gjtu0knKNCYiJwCbhFDIJMAwNyeAIVxyhthtWD7q8xSdG
b4ByOPv4nF/AOzC4MjihlQIILqSjhJILXcKnKdOd3EfWhJvuQ7f0GGqm7f8xzwNN
J8KLjWOuOI3yd7bjNCNZvnM=
-----END PRIVATE KEY-----
'''
