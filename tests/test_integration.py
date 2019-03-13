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


from nmoscommon.logger import Logger
from nmosoauth.auth_server.db_utils import drop_all
from nmosoauth.auth_server.security_api import SecurityAPI
from nmosoauth.auth_server.security_api import User
from data_for_tests import BEARER_TOKEN, TEST_PRIV_KEY
from base64 import b64encode

VERSION_ROOT = '/x-nmos/auth/v1.0'


class TestNmosOauth(unittest.TestCase):

    def setUp(self):
        self.api = SecurityAPI(logger=Logger("testing"), nmosConfig=None,
                               extraConfig={"OAUTH2_JWT_KEY": TEST_PRIV_KEY},
                               confClass='TestConfig')
        self.app = self.api.app
        self.client = self.app.test_client()

        self.mockUser = self.createMockUser("steve", "password")
        patcher = mock.patch("nmosoauth.auth_server.basic_auth.User")
        self.mockBasicUser = patcher.start()
        self.mockBasicUser.query.filter_by.return_value.first.return_value = self.mockUser
        self.addCleanup(patcher.stop)

    def tearDown(self):
        with self.app.app_context():
            drop_all()

    def createMockUser(self, username, password):
        tempUser = User()
        tempUser.username = username
        tempUser.password = password
        return tempUser

    def auth_headers(self, user):
        headers = {'Authorization': 'Basic ' + b64encode("{0}:{1}".format(user.username, user.password))}
        return headers

    def testInitialRoutes(self):

        with self.client as client:
            rv = client.get(VERSION_ROOT + '/', follow_redirects=True)
            self.assertEqual(rv.status_code, 200)
            rv = client.get(VERSION_ROOT + '/token', follow_redirects=True)
            self.assertEqual(rv.status_code, 405)
            rv = client.get(VERSION_ROOT + '/revoke', follow_redirects=True)
            self.assertEqual(rv.status_code, 405)
            rv = client.get(VERSION_ROOT + '/fetch_token/')
            self.assertEqual(rv.status_code, 302)
            rv = client.get(VERSION_ROOT + '/logout/')
            self.assertEqual(rv.status_code, 302)

    def testBasicAuthRoutes(self):

        headers = self.auth_headers(self.mockUser)
        with self.client as client:
            rv = client.get(VERSION_ROOT + '/register_client/')
            self.assertEqual(rv.status_code, 302)

            rv = client.post(VERSION_ROOT + '/register_client')
            self.assertEqual(rv.status_code, 401)

            wrongUser = self.createMockUser("bob", "pass")
            headers = self.auth_headers(wrongUser)
            rv = client.post(VERSION_ROOT + '/register_client', headers=headers)
            self.assertEqual(rv.status_code, 401)

    @mock.patch("nmosoauth.auth_server.security_api.render_template")
    @mock.patch("nmosoauth.auth_server.security_api.User")
    # @mock.patch("nmosoauth.auth_server.security_api.request")
    def testHome(self, mockUser, mockTemplate):

        mockTemplate.return_value = "test"

        with self.client.post(VERSION_ROOT + '/home/', data=dict(username="", password="")):
            mockTemplate.assert_called_with(
                'home.html', clients=None, message='Please Fill In Both Username and Password.', user=None)
        with self.client.post(VERSION_ROOT + '/home/', data=dict(username="steve", password="wrongpassword")):
            mockTemplate.assert_called_with(
                'home.html', clients=None, message='Invalid Password. Try Again.', user=None)
        with self.client.post(VERSION_ROOT + '/home/', data=dict(username="steve", password="password")) as rv:
            self.assertEqual(rv.status_code, 200)
        mockUser.query.filter_by.return_value.first.return_value = None
        with self.client.post(VERSION_ROOT + '/home/', data=dict(username="steve", password="password")):
            mockTemplate.assert_called_with(
                'home.html', clients=None, message='That username is not recognised. Please signup.', user=None)

    @mock.patch("nmosoauth.auth_server.security_api.authorization")
    def testTokenEndpoint(self, mockAuthServer):
        mockAuthServer.create_endpoint_response.return_value = BEARER_TOKEN


if __name__ == '__main__':
    unittest.main()
