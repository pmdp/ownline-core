import hashlib
import hmac
import json
import logging
import re
import time

import socket
from contextlib import closing

from ownline_core.core.actioners.port_forwarding_action import PortForwardingAction
from ownline_core.core.actioners.reverse_proxy_action import ReverseProxyAction
from ownline_core.core.exceptions import MessageValidationException, ActionExecutionException


class OwnlineAction(object):
    """
    Actioner for verifying, processing and executing requests
    """

    def __init__(self, config=None):
        self.logger = logging.getLogger("ownline_core_log")
        self.config = config
        self.reverse_proxy_action = ReverseProxyAction(config=self.config)
        self.port_forwarding_action = PortForwardingAction(config=self.config)

    def initialize(self):
        self.logger.info("Initializing firewall rules and reverse proxy configurations")
        reverse_result = self.reverse_proxy_action.initialize()
        port_result = self.port_forwarding_action.initialize()
        self.logger.info("Successfully initialization")
        return {"ok": reverse_result and port_result}

    def do_action(self, raw_message):
        # todo: check max and min message length before
        if len(raw_message) < 130:
            raise MessageValidationException("invalid message size")
        income_sign = raw_message[:128]
        income_cmd = raw_message[128:]

        result = {"ok": False}
        try:
            # Check for valid signature
            actual_signature = hmac.new(self.config.CMD_HMAC_KEY, income_cmd.encode('utf-8'), hashlib.sha512).hexdigest()
            if not hmac.compare_digest(income_sign, actual_signature):
                self.logger.error("Invalid message signature")
                raise MessageValidationException("invalid signature found")

            cmd = json.loads(income_cmd)
            if 'action' not in cmd.keys():
                raise MessageValidationException("action key does not exist")
            if cmd['action'] not in ['ini', 'ping', 'flush'] and 'payload' not in cmd.keys():
                raise MessageValidationException(f"payload is necessary for this action: {cmd['action']}")

            if cmd['action'] == 'ini':
                result = self.initialize()
            elif cmd['action'] == 'add':
                result = self.do_add(cmd['payload'])
            elif cmd['action'] == 'del':
                result = self.do_del(cmd['payload'])
            elif cmd['action'] == 'flush':
                result = self.do_flush()
            elif cmd['action'] == 'ping':
                result = {'ok': True, 'time': round(time.time() * 1000)}
            else:
                self.logger.error("Invalid action")

        except ActionExecutionException as e1:
            self.logger.error(f"{e1!r}")
            result["reason"] = f"{e1!r}"
        except MessageValidationException as e2:
            self.logger.error(f"{e2!r}")
            result["reason"] = f"{e2!r}"
        except Exception as e3:
            self.logger.error(f"{e3!r}")
            result["reason"] = f"{e3!r}"
        finally:
            self.logger.debug(f"Result from ownline: {result}")
            return result

    def do_add(self, payload):
        trusted_ip = payload['trusted_ip']
        service = payload['service']
        fixed_port_dst = payload['port_dst']
        action_result = False
        if not re.compile(self.config.IP_V4_REGEX_CIDR).match(trusted_ip) \
                and not trusted_ip == self.config.LAN_NETWORK:
            raise MessageValidationException(f"Invalid trusted_ip: {trusted_ip}")

        if 'service' not in payload.keys():
            raise MessageValidationException("No service provided")

        if type(payload['service']) is not dict:
            raise MessageValidationException(f"Invalid service type, spects a dict, found: {type(payload['service'])}")

        service_attributes = ['name', 'protocol', 'transport_protocol',
                              'ip_dst_lan', 'port_dst_lan',
                              'type', 'connection_upgrade',
                              'custom_nginx_template']

        for key in payload['service'].keys():
            if key not in service_attributes:
                raise MessageValidationException(f"Invalid service attribute: {key}")

        for key in service_attributes:
            if key not in payload['service'].keys():
                raise MessageValidationException(f"non-existent necessary service attribute: {key}")

        if fixed_port_dst is None:
            port_dst = self.get_free_random_port()
        else:
            if not isinstance(fixed_port_dst, int) or fixed_port_dst > self.config.MAX_PORT \
                    or fixed_port_dst < self.config.MIN_PORT:
                raise MessageValidationException(f"Invalid service port received: {fixed_port_dst}")
            port_dst = fixed_port_dst

        if service['type'] == "proxy":
            action_result = self.reverse_proxy_action.do_add(trusted_ip, service, port_dst)
        elif service['type'] == "port_forwarding":
            action_result = self.port_forwarding_action.do_add(trusted_ip, service, port_dst)

        if not action_result:
            raise ActionExecutionException(f"bad action result from type: {payload['service']['type']}")
        else:
            if fixed_port_dst is None:
                return {"ok": True, "port_dst": port_dst}
            else:
                return {"ok": True}

    def do_del(self, payload):
        action_result = False
        if payload['service']['type'] == "proxy":
            action_result = self.reverse_proxy_action.do_del(payload)
        elif payload['service']['type'] == "port_forwarding":
            action_result = self.port_forwarding_action.do_del(payload)

        if not action_result:
            raise ActionExecutionException(f"bad action result from type: {payload['service']['type']}")
        else:
            return {"ok": True}

    def do_flush(self):
        self.logger.debug("Removing all sessions")
        flush_reverse_proxy = self.reverse_proxy_action.do_flush()
        flush_port_forwarding = self.port_forwarding_action.do_flush()
        self.logger.info("All sessions removed")
        response = {"ok": flush_reverse_proxy and flush_port_forwarding,
                    'reverse_proxy_flush': flush_reverse_proxy,
                    'port_forwarding_flush': flush_port_forwarding}
        return response

    @staticmethod
    def get_free_random_port():
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.bind(('', 0))
            return s.getsockname()[1]

