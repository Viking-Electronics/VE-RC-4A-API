import requests
import socket
import logging
from enum import Enum
import requests
from requests.auth import HTTPDigestAuth

VIKING_MAC_ADDR_PREFIX = "18-E8-0F"
VIKING_RC4A_MODEL_STR = "Viking RC-4A"
BROADCAST_ADDR = "255.255.255.255"
BROADCAST_PORT = 30303
BROADCAST_MESSAGE = "Discovery: Who is out there?"
MAX_MSG_SIZE = 512
C_RELAY_COMMAND_STRUCTURE = "/protect/relays.cgi?relay=%d&%s=%s"
C_RELAY_QUERY_STATUS_STRUCTURE = "/protect/status.xml"
C_RELAY_COMMAND_STATE = "state"
C_RELAY_COMMAND_TIME = "time"
C_RELAY_COMMAND_STATE_ON = "on"
C_RELAY_COMMAND_STATE_OFF = "off"
C_RELAY_COMMAND_STATE_TOGGLE = "toggle"
C_HTTP_GET_URL_FORM = "http://%s:%d"


class Commands(Enum):
    RELAY_RESET = 0
    RELAY_SET = 1
    __RELAY_FLASH = 2
    RELAY_TIMED = 3
    RELAY_TOGGLE = 4
    STATUS = 10
    


class NetworkRelay:
    def __init__(self, name, ip, port, mac):
        self.name = name
        self.ip = ip
        self.mac = mac
        self.port = port
        self.username = "admin"
        self.password = "viking"
        self.digest_auth_required = False

    def __str__(self):
        return self.name + ":" + self.ip + ":" + self.mac

    def __send_command(self, index, command, state = None, duration = None):
        if command not in Commands:
            raise ValueError("Invalid command")
        
        if command == Commands.RELAY_RESET:
            formatted_command = C_RELAY_COMMAND_STRUCTURE % (index, C_RELAY_COMMAND_STATE, C_RELAY_COMMAND_STATE_OFF)
        elif command == Commands.RELAY_SET:
            formatted_command = C_RELAY_COMMAND_STRUCTURE % (index, C_RELAY_COMMAND_STATE, C_RELAY_COMMAND_STATE_ON)
        elif command == Commands.RELAY_TIMED:
            formatted_command = C_RELAY_COMMAND_STRUCTURE % (index, C_RELAY_COMMAND_TIME, str(int(duration)))
        elif command == Commands.RELAY_TOGGLE:
            formatted_command = C_RELAY_COMMAND_STRUCTURE % (index, C_RELAY_COMMAND_STATE, C_RELAY_COMMAND_STATE_TOGGLE)
        elif command == Commands.STATUS:
            formatted_command = C_RELAY_QUERY_STATUS_STRUCTURE
        url = C_HTTP_GET_URL_FORM % (self.ip, self.port) + formatted_command
        
        try:
            request_auth_failed = False
            if not (self.digest_auth_required is True):
                resp = requests.get(url, auth=(self.username, self.password))
                if resp.status_code == 401:
                    request_auth_failed = True

            if request_auth_failed or self.digest_auth_required is True:
                resp = requests.get(url, auth=HTTPDigestAuth(self.username, self.password))
                if resp.status_code == 200:
                    self.digest_auth_required = True #remember for future requests

            return (resp.status_code, resp.text)
        except Exception as err:
            print("Exception thrown while sending command:", err)
            return None
        
    def set_credentials(self, username, password):
        self.username = username
        self.password = password

    def set_auth_digest(self):
        self.__digest_auth_required = True
    def set_auth_basic(self):
        self.__digest_auth_required = False

    def command(self, index, command, state = None, duration = None):
        return self.__send_command(index, command, state, duration)

    def get_inputs(self, index = None):
        #returns a list of tuples, where the first element is the index of the input and the second element is the name of the input
        #Parameters:
        #index: if not None, only the input with the specified index will be returned
        import xml.etree.ElementTree as ET 

        code, response = self.__send_command(0, Commands.STATUS)

        if code != 200:
            return None
        
        tree = ET.fromstring(response)
        inputs = []

        for i in range(1,5):
            input_value = tree.findtext(path='btn%d' % i)
            if i is index:
                return input_value
            else:
                inputs.append((i, input_value))

        return inputs

class RelayControl:
    @staticmethod
    def discover(timeout = 0.5):
        discovered_devices = []
        try:
            discovery_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            discovery_socket.settimeout(timeout)
            discovery_socket.bind(('', 0))
        except Exception as err:
            logging.exception("Exception while binding to port:")

        try:
            data = BROADCAST_MESSAGE.encode()
            discovery_socket.sendto(data, (BROADCAST_ADDR, BROADCAST_PORT))
            while(True):
                resp, (ip, port) = discovery_socket.recvfrom(MAX_MSG_SIZE)

                if len(resp) == 0:
                    continue #no data received

                str_resp = resp.decode('ascii')
                if (len(str_resp) == 0):
                    continue #no data decoded from response

                lines = str_resp.split()
                if len(lines) != 6:
                    continue #RC4A responds to the discovery message with 6 lines

                if VIKING_RC4A_MODEL_STR.encode() not in resp:
                    continue #not a Viking RC4A device

                mac = lines[2]
                if not mac.startswith(VIKING_MAC_ADDR_PREFIX):
                    continue #Doesn't have the Viking MAC address prefix

                device = NetworkRelay(lines[1], ip=ip, port=int(lines[0]), mac=mac)
                discovered_devices.append(device)

        except TimeoutError:
            pass #discovery has timed out
        except Exception as err:
            print("Exception thrown while performing discovery:", err)
        
        if len(discovered_devices) == 0:
            return None
        return discovered_devices
