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
import re
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

    def signup(self, username, password, is04, is05):
        return self.client.post('/signup',
                                data=dict(username=username, password=password,
                                          is04=is04, is05=is05),
                                follow_redirects=True)

    def login(self, username, password):
        return self.client.post('/',
                                data=dict(username=username, password=password),
                                follow_redirects=True)

    def logout(self):
        return self.client.get('/logout', follow_redirects=True)

    def test_flask_access(self):
        with self.client as c:
            rv = c.get('/')
            assert(b"OAuth2 Server" in rv.data)

    def test_signup_logout_login(self):
        user = 'test'
        password = 'testing'

        rv = self.signup(user, password, 'read', 'write')
        print(rv.data)
        assert('Logged in as' in rv.data)

        rv = self.logout()
        assert(b'Login / Signup' in rv.data)

        rv = self.login(user, password)
        regex = r'Logged in as.*' + user
        assert(re.search(regex, rv.data))


if __name__ == '__main__':
    unittest.main()
