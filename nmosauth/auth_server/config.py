# Copyright 2017 British Broadcasting Corporation
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

from __future__ import absolute_import
from __future__ import print_function

import os
import json
import copy

# HTTPS under test only at present
# enabled = Use HTTPS only in all URLs and mDNS adverts
# disabled = Use HTTP only in all URLs and mDNS adverts
# mixed = Use HTTP in all URLs, but additionally advertise an HTTPS endpoint for discovery of this API only
CONFIG_DEFAULTS = {
    "priority": 100,
    "https_mode": "disabled",
    "enable_mdns": True,
}

config = {}
config.update(copy.deepcopy(CONFIG_DEFAULTS))

try:
    config_file = "/etc/nmosauth/config.json"
    if os.path.isfile(config_file):
        f = open(config_file, 'r')
    if f:
        extra_config = json.loads(f.read())
        config.update(extra_config)
except Exception as e:
    print("Exception loading config: {}".format(e))
