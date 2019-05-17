#!/usr/bin/python
#
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

from __future__ import print_function
from __future__ import absolute_import
import unittest
import mock


from nmoscommon.logger import Logger
from nmosauth.auth_server.db_utils import drop_all
from nmosauth.auth_server.security_api import SecurityAPI
from nmosauth.auth_server.security_api import User
from nmos_auth_data import BEARER_TOKEN, TEST_PRIV_KEY
from base64 import b64encode

VERSION_ROOT = '/x-nmos/auth/v1.0'


class TestNmosAuth(unittest.TestCase):

    def setUp(self):
        self.api = SecurityAPI(logger=Logger("testing"), nmosConfig=None,
                               extraConfig={"OAUTH2_JWT_KEY": TEST_PRIV_KEY},
                               confClass='TestConfig')
        self.app = self.api.app
        self.client = self.app.test_client()

        self.mockUser = self.createMockUser("steve", "password")
        patcher = mock.patch("nmosauth.auth_server.basic_auth.User")
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
        auth_string = "{}:{}".format(user.username, user.password).encode('utf-8')
        headers = {
            'Authorization': b'Basic ' + b64encode(auth_string)
        }
        return headers

    def testGetInitialRoutes(self):

        with self.client as client:
            rv = client.get(VERSION_ROOT + '/', follow_redirects=True)
            self.assertEqual(rv.status_code, 200)
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

    @mock.patch("nmosauth.auth_server.security_api.render_template")
    @mock.patch("nmosauth.auth_server.security_api.User")
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

    @mock.patch("nmosauth.auth_server.security_api.authorization")
    def testTokenEndpoint(self, mockAuthServer):
        mockAuthServer.create_endpoint_response.return_value = BEARER_TOKEN


if __name__ == '__main__':
    unittest.main()
