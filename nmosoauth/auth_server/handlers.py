from authlib.common.errors import AuthlibBaseError, AuthlibHTTPError
# from authlib.flask.error import raise_http_exception
from flask import jsonify, render_template
from .db_utils import create_all


def register_handlers(app):

    # create all db tables
    with app.app_context():
        create_all()

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

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('404.html'), 404
