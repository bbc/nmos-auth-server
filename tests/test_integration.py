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
import mock

from nmosoauth.auth_server.db_utils import drop_all
from nmosoauth.auth_server.security_api import SecurityAPI
from nmosoauth.auth_server.security_api import User
from data_for_tests import BEARER_TOKEN


class TestNmosOauth(unittest.TestCase):

    def setUp(self):
        self.api = SecurityAPI(None, None, 'TestConfig')
        self.app = self.api.app
        self.client = self.app.test_client()

    def tearDown(self):
        with self.app.app_context():
            drop_all()

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

    @mock.patch("nmosoauth.auth_server.security_api.render_template")
    @mock.patch("nmosoauth.auth_server.security_api.User")
    # @mock.patch("nmosoauth.auth_server.security_api.request")
    def testHome(self, mockUser, mockTemplate):
        tempUser = User()
        tempUser.username = "steve"
        tempUser.password = "password"

        mockUser.query.filter_by.return_value.first.return_value = tempUser
        mockTemplate.return_value = "test"

        with self.client.post('/', data=dict(username="", password="")):
            mockTemplate.assert_called_with(
                'home.html', clients=None, message='Please Fill In Both Username and Password.', user=None)
        with self.client.post('/', data=dict(username="steve", password="wrongpassword")):
            mockTemplate.assert_called_with(
                'home.html', clients=None, message='Invalid Password. Try Again.', user=None)
        with self.client.post('/', data=dict(username="steve", password="password")) as rv:
            self.assertEqual(rv.status_code, 302)
        mockUser.query.filter_by.return_value.first.return_value = None
        with self.client.post('/', data=dict(username="steve", password="password")):
            mockTemplate.assert_called_with(
                'home.html', clients=None, message='That username is not recognised. Please signup.', user=None)

    @mock.patch("nmosoauth.auth_server.security_api.authorization")
    def testTokenEndpoint(self, mockAuthServer):
        mockAuthServer.create_endpoint_response.return_value = BEARER_TOKEN


if __name__ == '__main__':
    unittest.main()
