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
import json
from os import environ
from base64 import b64encode
from six.moves.urllib.parse import parse_qs
from six import string_types
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash, check_password_hash

from nmoscommon.logger import Logger
from nmosauth.auth_server.db_utils import drop_all
from nmosauth.auth_server.models import AdminUser
from nmosauth.auth_server.security_api import SecurityAPI
from nmos_auth_data import TEST_PRIV_KEY

environ["AUTHLIB_INSECURE_TRANSPORT"] = "1"

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
        self.client_metadata = None

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
        user.password = generate_password_hash(password)
        user.id = self.user_id = self.user_id + 1
        return user

    def auth_headers(self, username, password):
        auth_string = "{}:{}".format(username, password).encode('utf-8')
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
            rv = client.get(VERSION_ROOT + '/register/', headers=headers)
            self.assertEqual(rv.status_code, 302)
            # Posting to Register client returns 401 if not expecting html
            with self.assertRaises(HTTPException) as http_error:
                rv = client.post(VERSION_ROOT + '/register')
                self.assertEqual(http_error.exception.code, 401)
                rv = client.post(VERSION_ROOT + '/authorize')
                self.assertEqual(http_error.exception.code, 401)

    @mock.patch("nmosauth.auth_server.security_api.getAdminUser")
    def testBasicAuthRoutes(self, mockGetAdminUser):

        mockGetAdminUser.return_value = self.testUser
        headers = self.auth_headers(TEST_USERNAME, TEST_PASSWORD)
        with self.client as client:
            # Get /register_client returns 200 status code
            rv = client.get(VERSION_ROOT + '/register/', headers=headers)
            self.assertEqual(rv.status_code, 200)
            mockGetAdminUser.assert_called_with(self.testUser.username)

            # Get /register_client with incorrect credentials returns Unauthorized
            headers = self.auth_headers("bob", "wrong_password")
            with self.assertRaises(HTTPException) as http_error:
                client.get(VERSION_ROOT + '/register/', headers=headers)
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

    def testRegisteringClientAndTokenEndpoint(self):

        # TEST SIGNING UP ADMIN USER
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
                self.assertTrue(check_password_hash(AdminUser.query.get(1).password, TEST_PASSWORD))

        # TEST REGISTERING CLIENT
        register_data = {
            'client_name': 'R&D Web Router',
            'client_uri': 'http://ipstudio-master.rd.bbc.co.uk/ips-web/#/web-router',
            'scope': 'registration query',
            'redirect_uris': ['http://www.example.com'],
            'grant_types': ['password', 'authorization_code', 'refresh_token'],
            'response_types': ['code'],
            'token_endpoint_auth_method': 'client_secret_basic'
        }
        user_headers = self.auth_headers(TEST_USERNAME, TEST_PASSWORD)
        with self.client as client:
            with client.session_transaction() as sess:
                del sess['id']

            rv = client.post(
                VERSION_ROOT + '/register', json=register_data, headers=user_headers, follow_redirects=True)
            self.assertEqual(rv.status_code, 201, rv.data)
            self.client_metadata = json.loads(rv.get_data(as_text=True))
            self.assertTrue(b'client_id' in rv.data)
            self.assertTrue(b'client_secret' in rv.data)

        # TEST PASSWORD GRANT
        password_request_data = {
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD,
            "grant_type": "password",
            "scope": "registration"
        }
        self.assertTrue(self.client_metadata)  # Check client data is available
        client_headers = self.auth_headers(self.client_metadata["client_id"], self.client_metadata["client_secret"])

        with self.client.post(VERSION_ROOT + '/token', data=password_request_data, headers=client_headers) as rv:
            password_response = json.loads(rv.get_data(as_text=True))
            self.assertEqual(rv.status_code, 200, rv.data)
            self.assertTrue(
                all(i in password_response for i in (
                    "access_token", "refresh_token", "expires_in", "scope", "token_type"
                ))
            )
            self.assertEqual(password_response["token_type"].lower(), "bearer")

        # TEST AUTH CODE GRANT - AUTHORIZE ENDPOINT
        auth_code_request_params = {
            "response_type": "code",
            "client_id": self.client_metadata["client_id"],
            "redirect_uri": self.client_metadata["redirect_uris"][0],
            "scope": "registration",
            "state": "xyz"
        }

        auth_code_request_data = {
            "confirm": "true"
        }

        with self.client.post(
            VERSION_ROOT + '/authorize', data=auth_code_request_data,
            headers=user_headers, query_string=auth_code_request_params
        ) as rv:
            authorize_headers = rv.headers
            self.assertEqual(rv.status_code, 302, rv.data)
            self.assertTrue("location" in authorize_headers)
            self.assertTrue("error" not in authorize_headers["location"] and "code" in authorize_headers["location"])

            redirect_uri, query_string = rv.headers["location"].split('?')
            self.assertEqual(redirect_uri, register_data["redirect_uris"][0])

            parsed_query = parse_qs(query_string)
            auth_code = parsed_query["code"][0]
            self.assertTrue(isinstance(auth_code, string_types))
            state = parsed_query["state"][0]
            self.assertTrue(state, auth_code_request_params["state"])

        # TEST AUTH CODE GRANT - TOKEN ENDPOINT
        auth_grant_request_data = {
            "grant_type": "authorization_code",
            "redirect_uri": self.client_metadata["redirect_uris"][0],
            "code": auth_code
        }

        with self.client.post(VERSION_ROOT + '/token', data=auth_grant_request_data, headers=client_headers) as rv:
            auth_token_response = json.loads(rv.get_data(as_text=True))
            self.assertEqual(rv.status_code, 200, auth_token_response)
            self.assertTrue(
                all(i in auth_token_response for i in (
                    "access_token", "refresh_token", "expires_in", "scope", "token_type"
                ))
            )


if __name__ == '__main__':
    unittest.main()
