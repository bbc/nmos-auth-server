import os
from flask import Flask
from flask_cors import CORS
from models import db
from oauth2 import config_oauth
from routes import bp


def create_app(confClass='BaseConfig', config=None):
    app = Flask(__name__.split('.')[0])

    # load configuration
    app.config.from_object('oauth2_server.settings.' + confClass)
    # load environment configuration
    if 'WEBSITE_CONF' in os.environ:
        app.config.from_envvar('WEBSITE_CONF')

    # load app specified configuration
    if config is not None:
        if isinstance(config, dict):
            app.config.update(config)
        elif config.endswith('.py'):
            app.config.from_pyfile(config)

    setup_app(app)
    return app


def setup_app(app):
    db.init_app(app)
    config_oauth(app)
    app.register_blueprint(bp, url_prefix='')
    CORS(app, origins=["http://localhost:5000", "http://127.0.0.1:5000"])
