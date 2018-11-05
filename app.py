from resource_server.conditional_security import ConditionalSecurity
from oauth2_server.app import create_app
from oauth2_server.db_utils import create_all, drop_all
from authlib.common.errors import AuthlibHTTPError
from flask import jsonify


app = create_app('BaseConfig')


@app.errorhandler(AuthlibHTTPError)
def error_handler(error):
    e = error()
    status = e[0]
    body = e[1]
    headers = e[2]
    print(error.message)
    return (jsonify(body), status, headers)


# The below only runs using python app.py
@app.route('/test')
@ConditionalSecurity(condition=True)
def hello_world():
    return 'Hello, World!'


@app.cli.command()
def initdb():
    create_all()


@app.cli.command()
def dropdb():
    drop_all()


# Run on network with 'python app.py'
if __name__ == "__main__":
    app.run(threaded=True, host='0.0.0.0', port=4999)
