#!/usr/bin/python
#
# Copyright 2018 British Broadcasting Corporation
#
# This is an internal BBC tool and is not licensed externally
# If you have received a copy of this erroneously then you do
# not have permission to reproduce it.

from __future__ import print_function
from __future__ import absolute_import
import unittest
# from mock import Mock
# from mock import patch

from oauth2_server.app import create_app
from oauth2_server.db_utils import create_all, drop_all


class FlaskTestCase(unittest.TestCase):

    def setUp(self):
        self.app = create_app('TestConfig')
        self.app.testing = True
        self.client = self.app.test_client()
        with self.app.app_context():
            create_all()

    @classmethod
    def setUpClass(cls):
        pass

    def tearDown(self):
        with self.app.app_context():
            drop_all()

    def login(self, username):
        return self.client.post('/', data=dict(
            username=username), follow_redirects=True)

    def logout(self):
        return self.client.get('/logout', follow_redirects=True)

    def test_flask_access(self):
        with self.client as c:
            rv = c.get('/')
            assert(b"OAuth2 Server" in rv.data)

    def test_login_logout(self):
        rv = self.login('dannym')
        assert b'Logged in as' in rv.data
        rv = self.logout()
        assert b'Login / Signup' in rv.data


if __name__ == '__main__':
    unittest.main()
