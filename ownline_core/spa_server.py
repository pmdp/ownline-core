import asyncio
import hashlib
import hmac
import ipaddress
import json
import re
import time
import logging
import geoip2.database
from geoip2.errors import AddressNotFoundError

from ownline_core.aes_cipher import AESCipher
from ownline_core.utils.http import do_request_to_ownline_web_api


class OwnlineSPAServer(asyncio.DatagramProtocol):
    def __init__(self, config):
        super().__init__()
        self.config = config
        self.transport = None
        # aes class for decrypt spa_packet
        self.aes = AESCipher(self.config.AES_KEY)
        self.logger = logging.getLogger("ownline_core_log")

    def connection_made(self, transport):
        self.logger.info(f'Connection made, transport: {transport}')
        self.transport = transport

    def datagram_received(self, data, addr):
        # Never answer SPA request to avoid port scannings and services discovers
        if self.verify_request(data, addr):
            self.do_request(data, addr[0])

    def error_received(self, exc):
        self.logger.error(f'Error received {exc}')

    def verify_request(self, request, client_address):
        self.logger.info(f"Incoming connection from {client_address}")
        try:
            ip_addr = ipaddress.ip_address(client_address[0])
            if ip_addr.is_loopback:
                self.logger.info(f"Accepting local connection from {client_address[0]}")
                return True
            elif ip_addr.is_private:
                net = ipaddress.ip_network(self.config.TRUSTED_NETWORK)
                if ip_addr in net:
                    self.logger.info(f"Accepting trusted network connection from {client_address[0]} at network {net}")
                    return True
                else:
                    return False
            elif ip_addr.is_global:
                with geoip2.database.Reader(self.config.GEO_IP_DATABASE_PATH) as reader:
                    response = reader.city(client_address[0])

                    iso_code = response.country.iso_code
                    country_name = response.country.name
                    #country_names = response.country.names['es-ES']
                    most_specific_name = response.subdivisions.most_specific.name
                    most_specific_iso_code = response.subdivisions.most_specific.iso_code
                    city_name = response.city.name
                    postal_code = response.postal.code
                    latitude = response.location.latitude
                    longitude = response.location.longitude
                    traits_network = response.traits.network

                    self.logger.info(f"iso_code: {iso_code}")
                    self.logger.info(f"country_name: {country_name}")
                    #self.logger.info(f"country_names: {country_names}")
                    self.logger.info(f"most_specific_name: {most_specific_name}")
                    self.logger.info(f"most_specific_iso_code: {most_specific_iso_code}")
                    self.logger.info(f"city_name: {city_name}")
                    self.logger.info(f"postal_code: {postal_code}")
                    self.logger.info(f"latitude: {latitude}")
                    self.logger.info(f"longitude: {longitude}")
                    self.logger.info(f"traits_network: {traits_network}")

                    if iso_code in ['ES']:
                        self.logger.info(f"Accepting IP from country '{iso_code}'")
                        return True
                    else:
                        self.logger.warning(f"IP from country '{iso_code}' not allowed")
                        return False
            else:
                self.logger.warning(f"Invalid IP '{ip_addr}'")
                return False

        except AddressNotFoundError as e:
            self.logger.warning(f"IP not in database {client_address[0]}")
            return False
        except Exception as e2:
            self.logger.error(f"Error verifying request: {e2}")
            return False

    def do_request(self, cipher_spa_packet, src_ip):
        err_msg = False
        try:
            self.logger.info(f"Incoming packet from IP: ({src_ip}) with length: {len(cipher_spa_packet)} and content:"
                             f" {str(cipher_spa_packet)}")
            # Raise exceptions for invalid spa_packet
            request = self.validate_and_process_spa_request(cipher_spa_packet, src_ip)
            if request:
                self.logger.info("Good SPA packet processed: " + str(request))
                self.logger.info(f"Requesting ownline-core SPA endpoint: POST {self.config.OWNLINE_WEB_SPA_ENDPOINT}")

                loop = asyncio.get_event_loop()
                task = loop.create_task(do_request_to_ownline_web_api(request,
                                                              self.config.OWNLINE_WEB_SPA_ENDPOINT_AUTH_TOKEN,
                                                              self.config.OWNLINE_WEB_SPA_ENDPOINT))
                self.logger.info(f"Request in progress: {task}")
        except json.JSONDecodeError as e1:
            err_msg = f"Invalid JSON: {e1}"
        except Exception as e2:
            err_msg = f"{e2}"
        finally:
            if err_msg:
                self.logger.error("Error doing request, reason: {}".format(err_msg))

    def validate_and_process_spa_request(self, cipher_spa_packet, src_ip):
        if len(cipher_spa_packet) < self.config.MIN_SPA_PACKET_LENGHT or len(cipher_spa_packet) > \
                self.config.MAX_SPA_PACKET_LENGHT:
            raise Exception("Invalid raw spa_packet length")
        if not src_ip or not re.compile(self.config.IP_V4_REGEX).match(src_ip):
            raise Exception(f"Invalid source IP: {src_ip}")
        # Separate sign and cipher spa_packet
        # CipherText = iv || aes(key1, iv, spa_packet)
        # sign = hmac(key2, ciphertext)
        # Final spa_packet = sign + CipherText
        signature = cipher_spa_packet[:128].decode('utf-8')
        spa_packet = cipher_spa_packet[128:]
        # Check for valid signature
        actual_signature = hmac.new(self.config.SPA_HMAC_KEY, spa_packet, hashlib.sha512).hexdigest()
        if not hmac.compare_digest(signature, actual_signature):
            raise Exception("Invalid spa_packet signature hmac comparation")
        # Decrypt spa_packet
        str_spa_packet = self.aes.decrypt(spa_packet)
        # Raise JSONDecodeError for invalid JSON
        obj_spa_packet = json.loads(str_spa_packet)

        if len(obj_spa_packet.keys()) != len(self.config.VALID_SPA_FIELDS):
            raise Exception("Invalid spa_packet keys number")

        for key in obj_spa_packet.keys():
            if key not in self.config.VALID_SPA_FIELDS:
                raise Exception(f"Invalid spa_packet key: {key}")

        if 'uid' not in obj_spa_packet.keys() or not re.compile(self.config.UUID_4_REGEX).match(obj_spa_packet['uid']):
            raise Exception("Invalid user id (uid): {}")

        if 'ts' not in obj_spa_packet.keys() or type(obj_spa_packet['ts']) != int\
                or not re.compile(self.config.TIMESTAMP_REGEX).match(str(obj_spa_packet['ts'])):
            raise Exception(f"Invalid timestamp (ts): {obj_spa_packet['ts']}")
        elif obj_spa_packet['ts'] < (round(time.time() * 1000) - self.config.MAX_SPA_DIFF_TS):
            raise Exception(f"Expired timestamp (ts): {obj_spa_packet['ts']}")

        obj_spa_packet['src_ip'] = src_ip

        return obj_spa_packet
