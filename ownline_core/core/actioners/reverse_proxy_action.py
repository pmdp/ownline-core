import asyncio
import logging
import os

from ownline_core.core.actioners.abstract_action import AbstractAction
from ownline_core.core.exceptions import ActionExecutionException
from ownline_core.utils.cmd import execute_command

SERVER_TEMPLATE = """
server {
\t#{{server_name}}

\tlisten {{port_dst}} ssl;
\t#{{next_listen_port}}

\tinclude /opt/etc/nginx/ssl_common.conf;
    
\tallow {{ip_src}};
\t#{{next_ip_src}}
\tdeny all;

\tlocation / {
\t\tproxy_set_header Host $host;
\t\tproxy_set_header X-Real-IP $remote_addr;
\t\tproxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
\t\tproxy_set_header X-Forwarded-Proto $scheme;
\t\tproxy_set_header X-Remote-Port $remote_port;
\t\tproxy_http_version  1.1;
\t\t#{{connection_upgrade}}
\t\tproxy_pass http://{{dst_lan}};
\t}
}
"""

CONNECTION_UPGRADE_TEMPLATE = """
\t\tproxy_set_header Upgrade $http_upgrade;
\t\tproxy_set_header Connection "upgrade";
"""

class ReverseProxyAction(AbstractAction):
    
    def __init__(self, config=None, **kwargs):
        super().__init__(**kwargs)
        self.logger = logging.getLogger("ownline_core_log")
        self.config = config

    def check_and_reload_chain(self):
        # check if reverse proxy chain exists
        cmd = [self.config.IPTABLES_BINARY, '-S', self.config.REVERSE_PROXY_CHAIN]
        ok, err, out = execute_command(cmd, self.config.CONFIG_NAME)
        # Create custom iptables chain if not exists
        if not ok:
            o2, stderr, stdout = execute_command([self.config.IPTABLES_BINARY, '-N', self.config.REVERSE_PROXY_CHAIN], self.config.CONFIG_NAME)
            if not ok:
                self.logger.warning("Creating new chain failed: {}".format(stderr))

        # Check if INPUT proxy chain rule set
        ok, stderr, stdout = execute_command([self.config.IPTABLES_BINARY, '-C', 'INPUT',
                                              '-m', 'state', '--state', 'NEW', '-j', self.config.REVERSE_PROXY_CHAIN], self.config.CONFIG_NAME)
        if not ok:
            ok, stderr, stdout = execute_command([self.config.IPTABLES_BINARY, '-I', 'INPUT', self.config.REVERSE_PROXY_CHAIN_RULENUM,
                                                  '-m', 'state', '--state', 'NEW', '-j', self.config.REVERSE_PROXY_CHAIN], self.config.CONFIG_NAME)
            if not ok:
                self.logger.error("Inserting input chain rule failed: {}".format(stderr))

    def initialize(self):
        self.logger.info("Initializing reverse proxy")

        self.check_and_reload_chain()

        # Check if exists services nginx config folder else create it
        if not os.path.exists(os.path.join(self.config.NGINX_CONFIG_PATH, self.config.NGINX_SERVERS_FOLDER)):
            os.makedirs(os.path.join(self.config.NGINX_CONFIG_PATH, self.config.NGINX_SERVERS_FOLDER))

        # Flush all rules
        return self.do_flush()

    def do_add(self, trusted_ip, service, port_dst):
        dst_lan = str(service['ip_dst_lan']) + ':' + str(service['port_dst_lan'])
        port_dst = str(port_dst)

        self.check_and_reload_chain()

        # Create iptables rule allowing nginx reverse proxy access
        # Doesnt matter if we repeat the iptables rule
        cmd = [self.config.IPTABLES_BINARY, '-A', self.config.REVERSE_PROXY_CHAIN, '-s', trusted_ip, '-p', 'tcp',
               '-m', 'tcp', '--dport', port_dst, '-j', 'ACCEPT']

        ok, err, out = execute_command(cmd, self.config.CONFIG_NAME)

        if ok:
            self.logger.info("Added reverse proxy iptables rule: {}".format(" ".join(cmd[1:])))

            filename = service['name'] + '.conf'
            service_file_path = os.path.join(self.config.NGINX_CONFIG_PATH, self.config.NGINX_SERVERS_FOLDER, filename)

            if os.path.isfile(service_file_path):
                # If file already exists is because a session is using it or is a persistent service
                # Read file data and concatenate new listen port (if necessary) and allowed ip_src
                with open(service_file_path, 'r+') as conf_file:
                    actual_state = conf_file.read()
                    new_state = actual_state
                    if actual_state.count('listen ' + port_dst + ' ssl;') == 0:
                        # Add new port if its not already set
                        new_state = new_state.replace('#{{next_listen_port}}\n', 'listen ' + port_dst + ' ssl;\n\t#{{next_listen_port}}\n')
                    # Add new ip_src (doesnt matter if is repeated)
                    new_state = new_state.replace('#{{next_ip_src}}\n', 'allow ' + trusted_ip + ';\n\t#{{next_ip_src}}\n')
                    conf_file.seek(0)
                    conf_file.truncate()
                    conf_file.write(new_state)
                    conf_file.flush()
                    os.fsync(conf_file.fileno())
                    self.logger.info("Updated config file: {}".format(service_file_path))
            else:
                # Create new server config from custom or default template
                if service['connection_upgrade']:
                    server_conf = SERVER_TEMPLATE
                    server_conf = server_conf.replace("#{{connection_upgrade}}", CONNECTION_UPGRADE_TEMPLATE)
                elif service['custom_nginx_template']:
                    server_conf = service['custom_nginx_template']
                else:
                    server_conf = SERVER_TEMPLATE

                server_conf = server_conf.replace("{{ip_src}}", trusted_ip)
                server_conf = server_conf.replace("{{port_dst}}", port_dst)
                server_conf = server_conf.replace("{{dst_lan}}", dst_lan)
                server_conf = server_conf.replace('#{{server_name}}', 'server_name ' + service['name'] + '.' + self.config.BASE_HOST_NAME + ';')

                with open(service_file_path, 'w') as config_file:
                    config_file.write(server_conf)
                    config_file.flush()
                    os.fsync(config_file.fileno())
                    self.logger.info("Created new config file: {}".format(service_file_path))

            # reload nginx
            if self.check_and_reload_nginx():
                return True
        else:
            raise ActionExecutionException("Failed reverse proxy access firewall rule adding execution: stderr: {} stout: {}".format(err, out))

    def do_del(self, session):
        ip_src = session['trusted_ip']
        port_dst = str(session['port_dst'])

        cmd = [self.config.IPTABLES_BINARY, '-D', self.config.REVERSE_PROXY_CHAIN, '-s', ip_src,
               '-p', 'tcp', '-m', 'tcp',
               '--dport', str(port_dst), '-j', 'ACCEPT']

        ok, err, out = execute_command(cmd, self.config.CONFIG_NAME)

        if ok:
            self.logger.info("Deleted reverse proxy iptables rule: {}".format(" ".join(cmd[1:])))
        else:
            raise ActionExecutionException("Error deleting reverse proxy iptables rule: stderr: {} stout: {}".format(err, out))

        filename = session['service']['name'] + '.conf'
        service_file_path = os.path.join(self.config.NGINX_CONFIG_PATH, self.config.NGINX_SERVERS_FOLDER, filename)
        delete = False
        try:
            with open(service_file_path, 'r+') as conf_file:
                actual_state = conf_file.read()
                if actual_state.count('allow') == 1:
                    # If is the last allow occurrence, delete the file
                    delete = True
                    # todo: only delete the file if it's the last session with this trusted ip,
                    #   this way multiple sessions can have the same trusted IP.
                    #   Retrieve this flag from ownline-web CMD action?
                else:
                    conf_file.seek(0)
                    conf_file.truncate()
                    new_state = actual_state.replace('allow ' + ip_src + ';\n', '', 1)
                    if actual_state.count('listen ') > 1:
                        new_state = new_state.replace('listen ' + port_dst + ' ssl;\n', '', 1)
                    conf_file.write(new_state)
                    conf_file.flush()
                    os.fsync(conf_file.fileno())
        except FileNotFoundError:
            self.logger.error("Service config file not found")
        if delete:
            os.remove(service_file_path)
            self.logger.info("Successful deleting {} file".format(filename))
        else:
            self.logger.info("Successful removing rule from service nginx config file")

        if self.check_and_reload_nginx():
            return True

    def do_flush(self):
        # Delete all rules for OWNLINE_REVERSE_PROXY chain

        self.logger.info("Flushing reverse proxy rules")
        ok, stderr, stdout = execute_command([self.config.IPTABLES_BINARY, '-F', self.config.REVERSE_PROXY_CHAIN], self.config.CONFIG_NAME)
        if not ok:
            raise ActionExecutionException("Flush execution failed: {}".format(stderr))
        # Delete all files inside directory servers.d/*.conf
        for file in os.listdir(self.config.NGINX_CONFIG_PATH + '/' + self.config.NGINX_SERVERS_FOLDER + '/'):
            file_path = os.path.join(self.config.NGINX_CONFIG_PATH + '/' + self.config.NGINX_SERVERS_FOLDER + '/', file)
            try:
                if os.path.isfile(file_path):
                    self.logger.debug("Removing nginx config file: {}".format(file_path))
                    os.remove(file_path)
            except Exception as e:
                self.logger.exception("Failed removing all config files")
        # Reload config
        self.check_and_reload_nginx()
        return True

    def check_and_reload_nginx(self):
        check_config_cmd = [self.config.NGINX_BINARY, '-t']
        ok, err, out = execute_command(check_config_cmd, self.config.CONFIG_NAME)
        if ok:
            reload_cmd = [self.config.NGINX_BINARY, '-s', 'reload']
            ok_reload, err_reload, out_reload = execute_command(reload_cmd, self.config.CONFIG_NAME)
            if ok_reload:
                self.logger.info("Successful check and reload nginx daemon")
                return True
            else:
                raise ActionExecutionException("Failed reloading nginx configuration: stderr: {}, stdout: {}".format(err_reload, out_reload))
        else:
            raise ActionExecutionException("Failed checking nginx configuration: stderr: {}, stdout: {}".format(err, out))
