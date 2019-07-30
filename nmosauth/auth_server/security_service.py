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

from __future__ import print_function, absolute_import
from gevent import monkey
monkey.patch_all()

import gevent  # noqa E402
import time  # noqa E402
import signal  # noqa E402
from socket import gethostname  # noqa E402
from os import getpid, path, environ   # noqa E402
import json  # noqa E402

from nmoscommon.httpserver import HttpServer  # noqa E402
from nmoscommon.mdns import MDNSEngine  # noqa E402
from nmoscommon.logger import Logger  # noqa E402
from .security_api import SecurityAPI  # noqa E402
from .config import config # noqa E402

environ["AUTHLIB_INSECURE_TRANSPORT"] = "1"

PORT = 4999
HOSTNAME = gethostname().split(".", 1)[0]
API_VERSIONS = ["v1.0"]

DNS_SD_HTTP_PORT = 80
DNS_SD_HTTPS_PORT = 443
DNS_SD_NAME = 'auth_' + str(HOSTNAME) + "_" + str(getpid())
DNS_SD_TYPE = '_nmos-auth._tcp'


class SecurityService:
    def __init__(self, logger=None):
        self.logger = Logger("nmosauth", logger)
        self.config = config
        self.running = False
        self.httpServer = None
        self.mdns = MDNSEngine()

    def start(self):
        if self.running:
            gevent.signal(signal.SIGINT, self.sig_handler)
            gevent.signal(signal.SIGTERM, self.sig_handler)

        self.mdns.start()

        priority = self.config["priority"]
        if not str(priority).isdigit():
            priority = 0

        if self.config["https_mode"] != "enabled" and self.config["enable_mdns"]:
            self.mdns.register(DNS_SD_NAME + "_http", DNS_SD_TYPE, DNS_SD_HTTP_PORT,
                               {"pri": priority,
                                "api_ver": ",".join(API_VERSIONS),
                                "api_proto": "http"})
        if self.config["https_mode"] != "disabled" and self.config["enable_mdns"]:
            self.mdns.register(DNS_SD_NAME + "_https", DNS_SD_TYPE, DNS_SD_HTTPS_PORT,
                               {"pri": priority,
                                "api_ver": ",".join(API_VERSIONS),
                                "api_proto": "https"})

        self.httpServer = HttpServer(
            SecurityAPI, PORT, '0.0.0.0', api_args=[self.logger, self.config, 'ProductionConfig', None]
        )
        self.httpServer.start()
        while not self.httpServer.started.is_set():
            self.logger.writeInfo('Waiting for httpserver to start...')
            self.httpServer.started.wait()

        if self.httpServer.failed is not None:
            raise self.httpServer.failed

        self.logger.writeInfo("Running on port: {}".format(self.httpServer.port))

    def run(self):
        self.running = True
        self.start()
        while self.running:
            time.sleep(1)
        self._cleanup()

    def _cleanup(self):
        if self.mdns:
            try:
                self.mdns.stop()
                self.mdns.close()
                self.logger.writeInfo("mDNS stopped gracefully")
            except Exception as e:
                self.logger.writeWarning("Could not stop mDNS gracefully: {}".format(e))

        self.httpServer.stop()
        self.logger.writeInfo("Stopped Http Server")

    def sig_handler(self):
        self.logger.writeInfo('Pressed ctrl+c')
        self.stop()

    def stop(self):
        self.running = False
        self._cleanup()


if __name__ == '__main__':
    Service = SecurityService()
    Service.run()
