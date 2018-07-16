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

import os
from nmoscommon.webapi import WebAPI, route, basic_route
from flask import request, abort, Response, redirect, jsonify
from jsonschema import validate, FormatChecker, ValidationError, SchemaError
from abstractDevice import StagedLockedException
from sdpManager import SdpManager
import traceback
import json
from activator import Activator

from constants import SCHEMA_LOCAL

from functools import wraps
from flask_jwt_simple import (
    JWTManager, jwt_required, create_jwt, get_jwt, get_jwt_identity
)
from constants import JWT_PUBLIC_KEY, JWT_PRIVATE_KEY

__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))

QUERY_APINAMESPACE = "x-nmos"
QUERY_APINAME = "connection"
QUERY_APIVERSION = "v1.0"


DEVICE_ROOT = '/' + QUERY_APINAMESPACE +'/'+QUERY_APINAME+'/'+QUERY_APIVERSION+'/'
SINGLE_ROOT = DEVICE_ROOT + "single/"
BULK_ROOT = DEVICE_ROOT + "bulk/"


def role_required(roles):
    def role_decorator(func):
        @wraps(func)
        @jwt_required
        def wrapper(*args, **kwargs):
            print "start"
            jwt_data = get_jwt()
            if jwt_data['client'] == "controller" and jwt_data['scope'] == control:
                return func(*args, **kwargs)
            return (400, jsonify({"msg": "You don't have permission"}))
        return wrapper
return role_decorator


class ConnectionManagementAPI(WebAPI):

    def __init__(self, logger):
        super(ConnectionManagementAPI, self).__init__()
        self.logger = logger
        self.senders = {}
        self.receivers = {}
        self.activators = {}
        self.transportManagers = {}
        self.schemaPath = SCHEMA_LOCAL
        self.useValidation = True # Used for unit testing

        self.app.config['JWT_ALGORITHM'] = 'RS256'
        self.app.config['JWT_PRIVATE_KEY'] = JWT_PRIVATE_KEY
        self.app.config['JWT_PUBLIC_KEY'] = JWT_PUBLIC_KEY
        self.jwt = JWTManager(self.app)

    def addSender(self, sender, uuid):
        if uuid in self.senders:
            raise DuplicateRegistrationException(
                "Sender already registered with uuid " + uuid
            )
        self.senders[uuid] = sender
        self.activators[uuid] = Activator([sender])
        return self.activators[uuid]

    def addReceiver(self, receiver, uuid):
        if uuid in self.receivers:
            raise DuplicateRegistrationException(
                "Receiver already registered with uuid " + uuid
            )
        self.receivers[uuid] = receiver
        if receiver.legs == 1:
            self.activators[uuid] = Activator([
                receiver,
                receiver.transportManagers[0]
            ])
        else:
            self.activators[uuid] = Activator([
                receiver,
                receiver.transportManagers[0],
                receiver.transportManagers[1]
            ])
        self.transportManagers[uuid] = receiver.transportManagers[0]
        return self.activators[uuid]

    def getDevice(self, sr, device):
        if sr == "receivers":
            return self.receivers[device]
        elif sr == "senders":
            return self.senders[device]
        else:
            raise LookupError

    def removeSender(self, uuid):
        del self.senders[uuid]
        del self.activators[uuid]

    def removeReceiver(self, uuid):
        del self.receivers[uuid]
        del self.activators[uuid]

    def getActivator(self, device):
        return self.activators[device]

    def getTransportManager(self, device):
        return self.transportManagers[device]

    def errorResponse(self, code, message, id=None):
        response = {
            "code": code,
            "error": message,
            "debug": traceback.extract_stack()
        }
        if id is not None:
            response['id'] = id
        return response

    @route('/')
    @role_required(['dev', 'admin'])
    def __index(self):
        return (200, [QUERY_APINAMESPACE+"/"])

    @route('/'+QUERY_APINAMESPACE+"/")
    @role_required(['dev', 'admin'])
    def __namespaceindex(self):
        return (200, [QUERY_APINAME+"/"])

    @route('/'+QUERY_APINAMESPACE+'/'+QUERY_APINAME+'/')
    @role_required(['dev', 'admin'])
    def __nameindex(self):
        return (200, ["v1.0/"])

    @route('/'+QUERY_APINAMESPACE+'/'+QUERY_APINAME+'/'+QUERY_APIVERSION+'/')
    @role_required(['dev', 'admin'])
    def __versionindex(self):
        obj = ["bulk/", "single/"]
        return (200, obj)

    @route(SINGLE_ROOT)
    @role_required(['dev', 'admin'])
    def __singleRoot(self):
        obj = ["senders/", "receivers/"]
        return (200, obj)

    @route(SINGLE_ROOT + '<sr>/')
    @role_required(['dev', 'admin'])
    def __deviceroot(self, sr):
        if sr == "receivers":
            keys = list(self.receivers.keys())
        elif sr == "senders":
            keys = list(self.senders.keys())
        else:
            return 404
        toReturn = []
        for key in keys:
            toReturn.append(key + "/")
        return toReturn

    @route(SINGLE_ROOT + '<sr>/<device>/', methods=['GET'])
    @role_required(['dev', 'admin'])
    def __deviceindex(self, device, sr):
        try:
            self.getDevice(sr, device)
        except:
            abort(404)
        obj = ['constraints/', 'staged/', 'active/']
        if sr == 'senders':
            obj.append('transportfile/')
        return(200, obj)

    @route(SINGLE_ROOT + '<sr>/<device>/constraints/', methods=['GET'])
    @role_required(['dev', 'admin'])
    def __constraints(self, sr, device):
        try:
            device = self.getDevice(sr, device)
        except:
            abort(404)
        return device.getConstraints()

    @route(SINGLE_ROOT + '<sr>/<device>/staged/',
           methods=['GET'])
    @role_required(['dev', 'admin'])
    def __staged_get(self, sr, device):
        try:
            deviceObj = self.getDevice(sr, device)
        except:
            abort(404)
        toReturn = deviceObj.stagedToJson()
        toReturn['activation'] = self.getActivator(device).getLastRequest()
        if sr == "receivers":
            transportManager = self.getTransportManager(device)
            toReturn['transport_file'] = transportManager.getStagedRequest()
        return toReturn

    @route(SINGLE_ROOT + '<sr>/<device>/staged',
           methods=['PATCH'])
    @role_required(['dev', 'admin'])
    def single_staged_patch(self, sr, device):
        obj = request.get_json()
        return self.staged_patch(sr, device, obj)

    def staged_patch(self, sr, device, obj):
        # First check the sender/receiver exists
        toReturn = {}
        try:
            deviceObj = self.getDevice(sr, device)
        except:
            return (404, {})
        try:
            self.validateAgainstSchema(obj, 'v1.0-{}-stage-schema.json'.format(sr[:-1]))
        except ValidationError as e:
            return (400, self.errorResponse(400, str(e)))
        # If reciever check if transport file must be applied
        if 'transport_file' in obj and sr == "receivers":
            ret = self.applyTransportFile(obj.pop('transport_file'), device)
            if ret[0] != 200:
                return ret
        # If transport params are present apply those next
        if 'transport_params' in obj:
            ret = self.applyTransportParams(obj['transport_params'], deviceObj)
            if ret[0] != 200:
                return ret
        # Device IDs come next, depending on sender/receiver
        if 'receiver_id' in obj and sr == "senders":
            ret = self.applyReceiverId(obj['receiver_id'], deviceObj)
            if ret[0] != 200:
                return ret
        if 'sender_id' in obj and sr == "receivers":
            ret = self.applySenderId(obj['sender_id'], deviceObj)
            if ret[0] != 200:
                return ret
        # Set master enable
        if 'master_enable' in obj:
            try:
                deviceObj.setMasterEnable(obj['master_enable'])
            except StagedLockedException:
                return (423, self.errorResponse(423, "Resource is locked due to a pending activation"))
        # Finally carry out activation if requested
        if 'activation' in obj:
            activationRet = self.applyActivation(obj['activation'], device)
            if activationRet[0] != 200 and activationRet[0] != 202:
                return activationRet
            toReturn = self.assembleResponse(sr, deviceObj, device, activationRet)
        else:
            toReturn = (200, self.__staged_get(sr, device))
        return toReturn

    def validateAgainstSchema(self, request, schemaFile):
        """Check a request against the sender patch schema"""
        # Validation may be disabled for unit testing purposes
        if self.useValidation:
            schema = self.schemaPath + schemaFile
            try:
                schemaPath = os.path.join(__location__, schema)
                with open(schemaPath) as json_data:
                    schema = json.loads(json_data.read())
            except EnvironmentError:
                raise IOError('failed to load schema file at:{}'.format(schemaPath))
            checker = FormatChecker(["ipv4", "ipv6"])
            validate(request, schema, format_checker=checker)

    def assembleResponse(self, sr, deviceObj, deviceId, activationRet):
        toReturn = deviceObj.stagedToJson()
        toReturn['activation'] = {}
        toReturn['activation'] = activationRet[1]
        if sr == "receivers":
            try:
                transportManager = self.getTransportManager(deviceId)
            except:
                return (500, self.errorResponse(500, "Could not find transport manager"))
            toReturn['transport_file'] = transportManager.getStagedRequest()
        return (activationRet[0], toReturn)

    def applyReceiverId(self, id, device):
        try:
            device.setReceiverId(id)
        except ValidationError as e:
            return self.errorResponse(400, str(e))
        except StagedLockedException:
            return (423, self.errorResponse(423, "Resource is locked due to a pending activation"))
        return (200, {})

    def applySenderId(self, id, device):
        try:
            device.setSenderId(id)
        except ValidationError as e:
            return (400, self.errorResponse(400, str(e)))
        except StagedLockedException:
            return (423, self.errorResponse(423, "Resource is locked due to a pending activation"))
        return (200, {})

    def applyTransportParams(self, request, device):
        try:
            device.patch(request)
        except ValidationError as err:
            return (400, {"code": 400, "error": str(err),
                          "debug": str(traceback.format_exc())})
        except StagedLockedException:
            return (423, self.errorResponse(423, "Resource is locked due to a pending activation"))
        return (200, {})

    def applyTransportFile(self, request, device):
        transportManager = self.getTransportManager(device)
        try:
            transportManager.update(request)
        except KeyError as err:
            return (400, self.errorResponse(400, str(err)))
        except ValueError as err:
            return (400, self.errorResponse(400, str(err)))
        except ValidationError as err:
            return (400, self.errorResponse(400, str(err)))
        except StagedLockedException as e:
            return (423, self.errorResponse(423, "Resource is locked due to a pending activation"))
        return (200, {})

    def applyActivation(self, request, uuid):
        try:
            activator = self.getActivator(uuid)
            toReturn = activator.parseActivationObject(request)
        except ValidationError as err:
            return (400, self.errorResponse(400, str(err)))
        except TypeError as err:
            return (500, self.errorResponse(500, str(err)))
        return toReturn

    @route(SINGLE_ROOT + '<sr>/<device>/active/', methods=['GET'])
    @role_required(['dev', 'admin'])
    def __activeReceiver(self, sr, device):
        try:
            deviceObj = self.getDevice(sr, device)
        except:
            abort(404)
        toReturn = {}
        toReturn = deviceObj.activeToJson()
        toReturn['activation'] = self.getActivator(device).getActiveRequest()
        if sr == "receivers":
            transportManager = self.getTransportManager(device)
            toReturn['transport_file'] = transportManager.getActiveRequest()
        return toReturn

    @basic_route(SINGLE_ROOT + 'senders/<device>/transportfile/')
    @role_required(['dev', 'admin'])
    def __transportFileRedirect(self, device):
        try:
            device = self.getDevice('senders', device)
        except:
            abort(404)
        resp = Response(device.transportFile)
        resp.headers['content-type'] = 'application/sdp'
        return resp

    """Begin bulk API routes"""

    @route(BULK_ROOT)
    @role_required(['dev', 'admin'])
    def __bulk_root(self):
        return ['senders/', 'receivers/']

    @route(BULK_ROOT + '<sr>',
           methods=['POST'])
    @role_required(['dev', 'admin'])
    def __bulk_senders_staged_patch(self, sr):
        """Process a bulk staging object and sindicate it out to individual
        senders/receivers"""
        obj = request.get_json()
        statuses = []
        try:
            for entry in obj:
                try:
                    id = entry['id']
                except KeyError as err:
                    message = "Failed to find field 'id' in one or more objects"
                    return (400, self.errorResponse(400, message))
                try:
                    params = entry['params']
                except KeyError as err:
                    message = "Failed to find field 'params' in one or more objects"
                    return (400, self.errorResponse(400, message))
                res = self.staged_patch(sr, id, params)
                statuses.append({"id": id, "code": res[0]})
        except TypeError as err:
            return (400, {"code": 400, "error": str(err),
                          "debug": str(traceback.format_exc())})
        return (200, statuses)

    # The below is not part of the API - it is used to make the active
    # SDP file available over HTTP to BBC R&D RTP Receivers
    @basic_route(SINGLE_ROOT + 'receivers/<device>/active/sdp/')
    @role_required(['dev', 'admin'])
    def __active_sdp(self, device):
        try:
            receiver = self.receivers[device]
            manager = receiver.transportManagers[0]
        except:
            abort(404)
        resp = Response(manager.getActiveSdp())
        resp.headers['content-type'] = 'application/sdp'
        return resp


class DuplicateRegistrationException(BaseException):
    pass
