from authlib.common.errors import AuthlibBaseError, AuthlibHTTPError
# from authlib.flask.error import raise_http_exception
from flask import jsonify, render_template, abort, Response
from werkzeug.exceptions import HTTPException


def register_handlers(app):

    @app.errorhandler(AuthlibHTTPError)
    def authlib_http_handler(error):
        e = error()
        status = e[0]
        body = e[1]
        headers = e[2]
        return (jsonify(body), status, headers)

    @app.errorhandler(AuthlibBaseError)
    def authlib_base_handler(error):
        return jsonify(error=str(error)), 400

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('404.html', code=4, message="Not Found"), 404

    @app.errorhandler(403)
    def page_forbiddon(e):
        return render_template('404.html', code=3, message="Forbiddon"), 403

    @app.errorhandler(401)
    def page_unauthorised(e):
        return render_template('404.html', code=1, message="Unauthorised"), 401
