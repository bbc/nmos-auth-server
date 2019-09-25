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
from werkzeug.exceptions import HTTPException

from nmoscommon.logger import Logger
from nmosauth.auth_server.db_utils import drop_all
from nmosauth.auth_server.models import AdminUser
from nmosauth.auth_server.security_api import SecurityAPI
from nmos_auth_data import TEST_PRIV_KEY
from base64 import b64encode

VERSION_ROOT = '/x-nmos/auth/v1.0'
TEST_USERNAME = 'steve'
TEST_PASSWORD = 'password'


class TestNmosAuthServer(unittest.TestCase):

    def setUp(self):
        self.api = SecurityAPI(logger=Logger("testing"), nmosConfig=None,
                               extraConfig={"OAUTH2_JWT_KEY": TEST_PRIV_KEY},
                               confClass='TestConfig')
        self.app = self.api.app
        self.client = self.app.test_client()

        self.user_id = 0
        self.testUser = self.createUser(TEST_USERNAME, TEST_PASSWORD)
        # Boilerplate for mocking out Basic Auth user for the whole class
        patcher = mock.patch("nmosauth.auth_server.basic_auth.AdminUser")
        self.mockBasicUser = patcher.start()
        self.mockBasicUser.query.filter_by.return_value.first.return_value = self.testUser
        self.addCleanup(patcher.stop)

    def tearDown(self):
        with self.app.app_context():
            drop_all()

    def createUser(self, username, password):
        user = AdminUser()
        user.username = username
        user.password = password
        user.id = self.user_id = self.user_id + 1
        return user

    def auth_headers(self, user):
        auth_string = "{}:{}".format(user.username, user.password).encode('utf-8')
        headers = {
            'Authorization': b'Basic ' + b64encode(auth_string)
        }
        return headers

    def testGetInitialRoutes(self):

        headers = {"Accept": "text/html"}
        with self.client as client:
            # Correctly go to Home Page
            rv = client.get(VERSION_ROOT + '/', follow_redirects=True)
            self.assertEqual(rv.status_code, 200)
            # Authorize endpoint redirects to login
            rv = client.post(VERSION_ROOT + '/authorize', headers=headers)
            self.assertEqual(rv.status_code, 302)
            # Register client redirects to login page
            rv = client.get(VERSION_ROOT + '/register_client/', headers=headers)
            self.assertEqual(rv.status_code, 302)
            # Posting to Register client returns 401 if not expecting html
            with self.assertRaises(HTTPException) as http_error:
                rv = client.post(VERSION_ROOT + '/register_client')
                self.assertEqual(http_error.exception.code, 401)
                rv = client.post(VERSION_ROOT + '/authorize')
                self.assertEqual(http_error.exception.code, 401)

    @mock.patch("nmosauth.auth_server.security_api.getAdminUser")
    def testBasicAuthRoutes(self, mockGetAdminUser):

        mockGetAdminUser.return_value = self.testUser
        headers = self.auth_headers(self.testUser)
        with self.client as client:
            # Get /register_client returns 200 status code
            rv = client.get(VERSION_ROOT + '/register_client/', headers=headers)
            self.assertEqual(rv.status_code, 200)
            mockGetAdminUser.assert_called_with(self.testUser.username)

            # Get /register_client with incorrect credentials returns Unauthorized
            wrongUser = self.createUser("bob", "pass")
            headers = self.auth_headers(wrongUser)
            with self.assertRaises(HTTPException) as http_error:
                client.get(VERSION_ROOT + '/register_client/', headers=headers)
                self.assertEqual(http_error.exception.code, 401)

    @mock.patch("nmosauth.auth_server.security_api.render_template")
    @mock.patch("nmosauth.auth_server.security_api.getAdminUser")
    def testLogin(self, mockGetAdminUser, mockTemplate):

        mockTemplate.return_value = "test"
        mockGetAdminUser.return_value = self.testUser

        with self.client.post(VERSION_ROOT + '/login/', data=dict(username="", password="")):
            mockTemplate.assert_called_with(
                'login.html', message='Please Fill In Both Username and Password.')

        with self.client.post(VERSION_ROOT + '/login/', data=dict(username="steve", password="wrongpassword")):
            mockTemplate.assert_called_with(
                'login.html', message='Invalid Password. Try Again.')

        with self.client.post(VERSION_ROOT + '/login/', data=dict(username="steve", password="password")) as rv:
            self.assertEqual(rv.status_code, 302)

        mockGetAdminUser.return_value = None
        with self.client.post(VERSION_ROOT + '/login/', data=dict(username="steve", password="password")):
            mockTemplate.assert_called_with(
                'login.html', message='That username is not recognised. Please signup.')

    def testRegisterClient(self):

        # SignUp
        signup_data = {
            'username': TEST_USERNAME,
            'password': TEST_PASSWORD,
            'is04': 'read',
            'is05': 'write'
        }
        with self.client.post(VERSION_ROOT + '/signup', data=signup_data) as rv:
            self.assertEqual(rv.status_code, 302)
            with self.app.app_context():
                self.assertEqual(self.testUser.username, AdminUser.query.get(1).username)
                self.assertEqual(self.testUser.password, AdminUser.query.get(1).password)

        # Register Client
        register_data = {
            'client_name': 'R&D Web Router',
            'client_uri': 'http://ipstudio-master.rd.bbc.co.uk/ips-web/#/web-router',
            'scope': 'is04 is05',
            'redirect_uri': 'www.example.com',
            'grant_type': 'password',
            'response_type': 'code',
            'token_endpoint_auth_method': 'client_secret_basic'
        }
        headers = self.auth_headers(self.testUser)
        with mock.patch("nmosauth.auth_server.security_api.session") as mock_session:
            mock_session.__getitem__.return_value = None
            with self.client.post(VERSION_ROOT + '/register_client', data=register_data,
                                  headers=headers, follow_redirects=True) as rv:
                self.assertEqual(rv.status_code, 201)
                self.assertTrue(b'client_id' in rv.data)
                self.assertTrue(b'client_secret' in rv.data)


if __name__ == '__main__':
    unittest.main()
