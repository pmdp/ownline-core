#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-
import ssl

from ownline_core.aes_cipher import AESCipher

import argparse
import socket
import time
import json
import hashlib
import hmac
import logging

logger = logging.getLogger('ownline-spa-client')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Ownline SPA client')
    parser.add_argument('host', metavar='host', nargs='?', help='The host to connect')
    parser.add_argument('port', metavar='port', nargs='?', help='The port to connect')
    parser.add_argument('--user-id', metavar='user_id', dest='user_id', help='The user UUID')
    parser.add_argument('--aes-key', metavar='aes_key', dest='aes_key', help='The AES key')
    parser.add_argument('--hmac-key', metavar='hmac_key', dest='hmac_key', help='The HMAC key')
    parser.add_argument('--host-name', metavar='host_name', dest='host_name', help='The ownline core hostname')

    args = parser.parse_args()
    host = args.host
    port = int(args.port)
    user_id = args.user_id
    aes_key = args.aes_key
    # hmac_key = args.hmac_key.encode()
    host_name = args.host_name

    logger.info(f"Connecting to: {host}:{port}")
    # PROTOCOL_TLS_CLIENT requires valid cert chain and hostname
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    #context.load_verify_locations('path/to/cabundle.pem')
    #context.verify_mode = ssl.CERT_REQUIRED
    #context.load_cert_chain(certfile="./selfsigned.crt", keyfile="./selfsigned.key")
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    client_socket = socket.socket()
    secure_client_socket = context.wrap_socket(client_socket, server_hostname=host_name)
    secure_client_socket.connect((host, port))
    server_cert = secure_client_socket.getpeercert()
    # Validate whether the Certificate is indeed issued to the server
    # subject = dict(item[0] for item in server_cert['subject'])
    # commonName = subject['commonName']

    # if not server_cert:
    #     raise Exception("Unable to retrieve server certificate")
    #
    # if commonName != 'DemoSvr':
    #     raise Exception("Incorrect common name in server certificate")

    logger.info(f"Secure socket version: {secure_client_socket.version()}")
    # sock.connect((host, port))
    # sock.sendall(bytes("message", 'ascii'))

    # aes = AESCipher(aes_key)
    # message = {
    #     'uid': user_id,
    #     'ts': round(time.time() * 1000)
    # }
    message = {
        'action': 'ini'
    }
    message_txt = json.dumps(message, indent=None, separators=(',', ':'))
    logger.info(f"RAW message to SEND: {message_txt}")
    # CipherText = iv | | aes(key1, iv, message)
    # tag = hmac(key2, ciphertext)
    # cipher_content = aes.encrypt(message_txt)
    # actual_signature = hmac.new(hmac_key, cipher_content, hashlib.sha512).hexdigest()
    # final_message = actual_signature.encode() + cipher_content

    final_message = message_txt.encode('utf-8')
    logger.info(f"Final Message to SEND: {final_message}")
    secure_client_socket.send(final_message)
    response = secure_client_socket.recv(1024)
    logger.info(f"Received response: {response}")
    secure_client_socket.close()

