#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-

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
    parser.add_argument('--user-id', metavar='user_id', dest='user_id', required=True, help='The user UUID')
    parser.add_argument('--aes-key', metavar='aes_key', dest='aes_key', required=True, help='The AES key')
    parser.add_argument('--hmac-key', metavar='hmac_key', dest='hmac_key', required=True, help='The HMAC key')

    args = parser.parse_args()
    host = args.host
    port = int(args.port)
    user_id = args.user_id
    aes_key = args.aes_key
    hmac_key = args.hmac_key.encode()

    logger.info(f"Connecting to: {host}:{port}")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        #sock.connect((host, port))
        #sock.sendall(bytes("message", 'ascii'))

        aes = AESCipher(aes_key)
        message = {
            'uid': user_id,
            'ts': round(time.time() * 1000)
        }
        message_txt = json.dumps(message, indent=None, separators=(',', ':'))
        logger.info(f"RAW message to SEND: {message_txt}")
        # CipherText = iv | | aes(key1, iv, message)
        # tag = hmac(key2, ciphertext)
        cipher_content = aes.encrypt(message_txt)
        actual_signature = hmac.new(hmac_key, cipher_content, hashlib.sha512).hexdigest()
        final_message = actual_signature.encode() + cipher_content
        logger.info(f"Final Message to SEND: {final_message}")
        sock.sendto(final_message, (host, port))
