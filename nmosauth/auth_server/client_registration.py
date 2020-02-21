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

from flask import g
from authlib.oauth2.rfc7591 import ClientRegistrationEndpoint as _ClientRegistrationEndpoint

from .db_utils import addOAuthClient


class ClientRegistrationEndpoint(_ClientRegistrationEndpoint):

    def authenticate_user(self, request):
        return g.admin

    def create_endpoint_request(self, request):
        if "application/x-www-form-urlencoded" in request.headers["Content-Type"]:
            form_data = request.form.copy()
            for make_list in ["grant_types", "response_types", "redirect_uris"]:
                form_data[make_list] = form_data[make_list].splitlines()
            request.form = form_data
            return self.server.create_oauth2_request(request)
        else:
            return self.server.create_json_request(request)

    def save_client(self, client_info, client_metadata, user):
        return addOAuthClient(client_info, client_metadata, user)
