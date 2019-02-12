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

from nmosoauth.auth_server.db_utils import drop_all
from nmosoauth.auth_server.security_api import SecurityAPI


class TestNmosOauth(unittest.TestCase):

    def setUp(self):
        self.api = SecurityAPI(None, None, 'TestConfig')
        self.app = self.api.app
        self.client = self.app.test_client()

    def tearDown(self):
        with self.app.app_context():
            drop_all()

    def test_placeholder(self):
        test = 'test'
        assert('test' in test)

    def testRoutes(self):
        rv = self.client.get('/')
        self.assertEqual(rv.status_code, 200)
        rv = self.client.get('/token')
        self.assertEqual(rv.status_code, 405)
        rv = self.client.get('/revoke')
        self.assertEqual(rv.status_code, 405)
        rv = self.client.get('/register_client')
        self.assertEqual(rv.status_code, 302)
        rv = self.client.get('/fetch_token')
        self.assertEqual(rv.status_code, 302)


if __name__ == '__main__':
    unittest.main()
