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

from __future__ import print_function, absolute_import

import time
import signal
from socket import gethostname
from os import getpid
from systemd.daemon import notify, Notification

from nmoscommon.httpserver import HttpServer
from nmoscommon.mdns import MDNSEngine
from nmoscommon.logger import Logger
from nmoscommon.nmoscommonconfig import config as _config
from security_api import SecurityAPI

import gevent
from gevent import monkey
monkey.patch_all()

PORT = 4999
HOSTNAME = gethostname().split(".", 1)[0]
API_VERSIONS = ["v1.0"]

DNS_SD_HTTP_PORT = 80
DNS_SD_HTTPS_PORT = 443
DNS_SD_NAME = 'security_' + str(HOSTNAME) + "_" + str(getpid())
DNS_SD_TYPE = '_nmos-security._tcp'


class SecurityService:
    def __init__(self, logger=None):
        self.config = _config
        self.logger = Logger("security", logger)
        self.running = False
        self.httpServer = None
        self.mdns = MDNSEngine()

    def start(self):
        if self.running:
            gevent.signal(signal.SIGINT,  self.sig_handler)
            gevent.signal(signal.SIGTERM, self.sig_handler)

        self.mdns.start()

        priority = self.config["priority"]
        if not str(priority).isdigit() or priority < 100:
            priority = 0

        if self.config["https_mode"] != "enabled":
            self.mdns.register(DNS_SD_NAME + "_http", DNS_SD_TYPE, PORT,
                               {"pri": priority,
                                "api_ver": ",".join(API_VERSIONS),
                                "api_proto": "http"})
        if self.config["https_mode"] != "disabled":
            self.mdns.register(DNS_SD_NAME + "_https", DNS_SD_TYPE, PORT,
                               {"pri": priority,
                                "api_ver": ",".join(API_VERSIONS),
                                "api_proto": "https"})

        self.httpServer = HttpServer(SecurityAPI, PORT, '0.0.0.0', api_args=[self.logger, self.config])
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
        notify(Notification.READY)
        while self.running:
            time.sleep(1)
        self._cleanup()

    def _cleanup(self):
        if self.mdns:
            try:
                self.mdns.stop()
                self.mdns.close()
            except Exception as e:
                self.logger.writeWarning("Could not stop mdns: {}".format(e))

        self.httpServer.stop()
        self.logger.writeInfo("Stopped main()")

    def sig_handler(self):
        print('Pressed ctrl+c')
        self.stop()

    def stop(self):
        self.running = False


if __name__ == '__main__':
    Service = SecurityService()
    Service.run()
