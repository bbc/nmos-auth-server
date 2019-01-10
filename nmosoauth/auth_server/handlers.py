from authlib.common.errors import AuthlibBaseError, AuthlibHTTPError
# from authlib.flask.error import raise_http_exception
from db_utils import create_all, drop_all
from flask import jsonify


def register_handlers(app):

    @app.errorhandler(AuthlibHTTPError)
    def authlib_http_handler(error):
        e = error()
        status = e[0]
        body = e[1]
        headers = e[2]
        print(error.message)
        return (jsonify(body), status, headers)
        # return raise_http_exception(status, body, headers)

    @app.errorhandler(AuthlibBaseError)
    def authlib_base_handler(error):
        return jsonify(error=str(error)), 400

    @app.cli.command()
    def initdb():
        create_all()

    @app.cli.command()
    def dropdb():
        drop_all()
