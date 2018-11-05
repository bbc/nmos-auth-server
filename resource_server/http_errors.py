from flask import jsonify
from authlib.specs.rfc6749.errors import MissingAuthorizationError
from authlib.common.errors import AuthlibHTTPError


class ClientError(AuthlibHTTPError):
    status_code = 400

    def __init__(self, message, status_code=None, payload=None):
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return rv
