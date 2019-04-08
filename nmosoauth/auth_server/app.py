import os
from flask_cors import CORS
from .models import db
from .oauth2 import config_oauth
from .handlers import register_handlers
from .basic_auth import basicAuth


def config_app(app, confClass='BaseConfig', config=None):

    # load configuration
    settings = 'settings'
    if __package__ is not None:
        settings = __package__ + '.settings'
    app.config.from_object(settings + '.' + confClass)

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
    basicAuth.init_app(app)
    config_oauth(app)
    register_handlers(app)
    CORS(app)

    # create all db tables
    with app.app_context():
        db.create_all()
