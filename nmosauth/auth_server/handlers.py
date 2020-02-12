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

from flask import jsonify, render_template, request
from authlib.common.errors import AuthlibBaseError, AuthlibHTTPError


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

    @app.errorhandler(401)
    def page_unauthorised(e):
        return error_return(e, 401, "Unauthorised")

    @app.errorhandler(404)
    def page_not_found(e):
        return error_return(e, 404, "Page Not Found")

    @app.errorhandler(403)
    def page_forbiddon(e):
        return error_return(e, 403, "Forbidden")

    def error_return(e, code, message):
        if "Accept" in request.headers and "text/html" in request.headers.get("Accept"):
            return render_template('error.html', code=code, message=message), code
        else:
            raise e
