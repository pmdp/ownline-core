import os
import logging

basedir = os.path.abspath(os.path.dirname(__file__))


def get_env_or_def(env_name, default_value):
    # Return env_value if exists or default_value
    env_value = os.environ.get(env_name)
    return env_value if env_value else default_value


class Config(object):
    CONFIG_NAME = os.environ.get('OWNLINE_CORE_CONFIG_NAME') or 'development'
    # Daemon config
    PID_FILE = get_env_or_def('OWNLINE_CORE_PID_FILE', 'ownline_core.pid')

    BASE_HOST_NAME = get_env_or_def('OWNLINE_BASE_HOST_NAME', 'localhost')
    LAN_NETWORK = get_env_or_def('OWNLINE_LAN_NETWORK', '192.168.1.0/24')
    ALLOWED_TRANSPORT_PROTOCOLS = ('tcp', 'udp')

    # SPA UDP server
    SPA_SERVER_BIND_ADDRESS = get_env_or_def('OWNLINE_SPA_SERVER_BIND_ADDRESS', '0.0.0.0')
    SPA_SERVER_BIND_PORT = int(get_env_or_def('OWNLINE_SPA_SERVER_BIND_PORT', 54754))
    AES_KEY = get_env_or_def('OWNLINE_SPA_AES_KEY', '123')
    SPA_HMAC_KEY = get_env_or_def('OWNLINE_SPA_HMAC_KEY', '123').encode()
    TRUSTED_NETWORK = get_env_or_def('OWNLINE_SPA_TRUSTED_NETWORK', '10.0.0.0/24')
    GEO_IP_DATABASE_PATH = get_env_or_def('OWNLINE_GEO_IP_DATABASE_PATH', './GeoLite2-City.mmdb')
    MAX_SPA_DIFF_TS = int(get_env_or_def('OWNLINE_SPA_MAX_SPA_DIFF_TS_MINUTES', 1)) * 60 * 1000
    VALID_SPA_FIELDS = ['uid', 'ts']
    MIN_SPA_PACKET_LENGHT = 256
    MAX_SPA_PACKET_LENGHT = 256

    # SPA ownline-web endpoint
    OWNLINE_WEB_SPA_ENDPOINT = get_env_or_def('OWNLINE_WEB_SPA_ENDPOINT', 'http://localhost:5000/api/v1/spa')
    OWNLINE_WEB_SPA_ENDPOINT_AUTH_TOKEN = get_env_or_def('OWNLINE_WEB_SPA_ENDPOINT_AUTH_TOKEN', 'token')

    # core initialization ownline-web endpoint
    OWNLINE_WEB_CORE_INI_ENDPOINT = get_env_or_def('OWNLINE_WEB_CORE_INI_ENDPOINT', 'http://localhost:5000/api/v1/core/ini')


    # CMD TCP SSL ownline-web command server
    CMD_SERVER_BIND_ADDRESS = get_env_or_def('OWNLINE_CMD_SERVER_BIND_ADDRESS', '127.0.0.1')
    CMD_SERVER_BIND_PORT = int(get_env_or_def('OWNLINE_CMD_SERVER_BIND_PORT', 57329))
    CMD_SERVER_CERT_PATH = get_env_or_def('OWNLINE_CMD_SERVER_CERT_PATH', 'selfsigned.cert')
    CMD_SERVER_KEY_PATH = get_env_or_def('OWNLINE_CMD_SERVER_KEY_PATH', 'selfsigned.key')
    CMD_SERVER_CERT_PASSWORD = get_env_or_def('OWNLINE_CMD_SERVER_CERT_PASSWORD', 'Password1')
    CMD_HMAC_KEY = get_env_or_def('OWNLINE_CMD_HMAC_KEY', '123').encode()

    # iptables binary path
    IPTABLES_BINARY = get_env_or_def('IPTABLES_BINARY', '/sbin/iptables')

    # Port forwarding target chain
    PORT_FORWARDING_CHAIN = get_env_or_def('OWNLINE_PORT_FORWARDING_CHAIN', 'OWNLINE_FORWARDING_CHAIN')
    PORT_FORWARDING_CHAIN_RULENUM = get_env_or_def('OWNLINE_PORT_FORWARDING_CHAIN_RULENUM', '')

    # Nginx reverse proxy chain
    REVERSE_PROXY_CHAIN = get_env_or_def('OWNLINE_REVERSE_PROXY_CHAIN', 'OWNLINE_PROXY_CHAIN')
    REVERSE_PROXY_CHAIN_RULENUM = get_env_or_def('OWNLINE_REVERSE_PROXY_CHAIN_RULENUM', '8')

    # Reverse proxy with nginx
    NGINX_BINARY = get_env_or_def('NGINX_BINARY', '/bin/nginx')
    NGINX_CONFIG_PATH = get_env_or_def('NGINX_CONFIG_PATH', os.path.join(basedir, "nginx_dev"))
    NGINX_SERVERS_FOLDER = 'servers.d'

    # Regex
    UUID_4_REGEX = '[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}'
    IP_V4_REGEX = '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/32|)$'
    IP_V4_REGEX_CIDR = '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{2}$'
    TIMESTAMP_REGEX = '^\d{13}$'
    MIN_PORT = 5000
    MAX_PORT = 65535


class DevelopmentConfig(Config):
    DEBUG = True
    LOGGING_LEVEL = logging.DEBUG


class ProductionConfig(Config):
    DEBUG = False
    LOGGING_LEVEL = logging.INFO
    LOG_FILE = os.environ.get('OWNLINE_SPA_LOG_FILE') or 'log/ownline_core.log'


configuration = {
    'development': DevelopmentConfig,
    'production': ProductionConfig
}
