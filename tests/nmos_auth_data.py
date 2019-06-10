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

"""
EQUIVALENT TO:
{
  "sub": "dannym",
  "exp": 1582136965,
  "scope": "is-05",
  "iss": "http://rd.bbc.co.uk/x-nmos/auth/v1.0/",
  "iat": 1550579365,
  "x-nmos-api": {
    "access": "write",
    "name": "is-05"
  },
  "nbf": 1550579365,
  "aud": [
    "IS-05",
    "Write",
    "Access"
  ]
}
"""

BEARER_TOKEN = {
    "access_token": '''
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkYW5ueW0iLCJleHAi\
OjE1ODIxMzY5NjUsInNjb3BlIjoiaXMtMDUiLCJpc3MiOiJodHRwczovL29hdXRoL\
nJkLmJiYy5jby51ayIsImlhdCI6MTU1MDU3OTM2NSwieC1ubW9zLWFwaSI6eyJhY2\
Nlc3MiOiJ3cml0ZSIsIm5hbWUiOiJpcy0wNSJ9LCJuYmYiOjE1NTA1NzkzNjUsImF\
1ZCI6WyJJUy0wNSIsIldyaXRlIiwiQWNjZXNzIl19.UQYw_Br8uyYWYUbPSbZO3Bb\
hU16eOExZ2cZnIvOdp8lr0ZCZbytrKrEQr1ahZ3d49c9UxC0paK4FWYPHSZ3xxANh\
1AbhyR2ziybDtOM6rJ-5EdljhLaRLTeVpwhghP1QXwQj-vJWsFvqWAj13ij7S2ek8\
Uj_UHyrJoSjQniYDwZBB2mHoIl5MyX1yCo-h1tqCcdLZZY6RyIvVME6TUR_GzrMep\
g66DXfjVe7DDmcXH7hfhVMTdSu4N-z-ipV4L63RXjCEZbkY-_o-9houtzv-rSPFTc\
ILj_HC0Io8enTvnSYKgKOBEIjIZOMOFp68OEmqfjM1cBwV9TrKLO160U6tA\
''',
    "expires_in": 864000,
    "refresh_token": "Le2WDVvPvifiSq0sdsi7vGfmXwLPxkqhpfVsQrH1j9n4NxnU",
    "scope": "is04",
    "token_type": "Bearer"
}

CERT = {
    "default": '''-----BEGIN CERTIFICATE-----
MIIDYzCCAkugAwIBAgIJAOx6GjodUN5yMA0GCSqGSIb3DQEBCwUAMEgxCzAJBgNV
BAYTAlVLMRMwEQYDVQQHDApNYW5jaGVzdGVyMQwwCgYDVQQKDANCQkMxFjAUBgNV
BAMMDXd3dy5iYmMuY28udWswHhcNMTkwMjEyMTczNDM4WhcNMjAwMjEyMTczNDM4
WjBIMQswCQYDVQQGEwJVSzETMBEGA1UEBwwKTWFuY2hlc3RlcjEMMAoGA1UECgwD
QkJDMRYwFAYDVQQDDA13d3cuYmJjLmNvLnVrMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAyPkF31hSwpALcGS4NzZ2htdWUDSbK6CM6FvuLHDNPCDWq7XM
15gQPmvxNj2nuuo5q8e3s5EN9vxdHFiQLRivYcbqPJhQAnUQ6QuUEPWGo4HGv9C1
nFwbrUzGuLg1aSgj1yw1Fa6Ssykx3tb2UsN4cAKMHyadCUD5Tiv7FsC3RyMRXrua
+n8hofG9qWaxRfczc/NB6KnqXwiGHmEHyv0R3AiQiPVS9mVxFBcDCKOaArJlNdQP
HIjfpQ4u5P63ZRMw1PjequYnHkFssN33x/OyODvw3LiiOTuCAdmbNDvurO20PM0k
a9uhJd+Iv4vB3b3LV8aIgMUJCc5nE+JvWRhnUwIDAQABo1AwTjAdBgNVHQ4EFgQU
Ibb6XHJwMeobBcMfuNbpZRPJt+4wHwYDVR0jBBgwFoAUIbb6XHJwMeobBcMfuNbp
ZRPJt+4wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAVh5r453hcnIN
e4lW3eofej2BAVFGaZUznZgAlnAnWz4W/oI5MR1WgbyW/fJt+Dl9sbCe/+C5QpA1
GbjS5/Z6WCWC33Ury3PvgdrKGBb7yj7J7mRcaFBEfCKy8QWX68OHbm9UEUWlWPBc
Eoqgp4NwDD3+M78q90tlLRcspVlkDqnXdMkZk6lBlTi5ZHI2AcL9ZgbWvn45NQJ5
qUnYUPJAhnwUR77ZM9v4k7gOuOr9popfymVfhyWXV2PSbylWOXWplbO6bE23IMt9
Lr10BOtNHsqEg4nSE/AWodBJm82w5w3+eetMkcKQGXMwwp660Eioz0tX0v5oW2B0
zJnGbER/LQ==
-----END CERTIFICATE-----
'''
}

PUB_KEY = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyPkF31hSwpALcGS4NzZ2
htdWUDSbK6CM6FvuLHDNPCDWq7XM15gQPmvxNj2nuuo5q8e3s5EN9vxdHFiQLRiv
YcbqPJhQAnUQ6QuUEPWGo4HGv9C1nFwbrUzGuLg1aSgj1yw1Fa6Ssykx3tb2UsN4
cAKMHyadCUD5Tiv7FsC3RyMRXrua+n8hofG9qWaxRfczc/NB6KnqXwiGHmEHyv0R
3AiQiPVS9mVxFBcDCKOaArJlNdQPHIjfpQ4u5P63ZRMw1PjequYnHkFssN33x/Oy
ODvw3LiiOTuCAdmbNDvurO20PM0ka9uhJd+Iv4vB3b3LV8aIgMUJCc5nE+JvWRhn
UwIDAQAB
-----END PUBLIC KEY-----
'''

TEST_PRIV_KEY = '''-----BEGIN PRIVATE KEY-----
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
