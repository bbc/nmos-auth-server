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
