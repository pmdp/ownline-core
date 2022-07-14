import logging

from ownline_core.core.actioners.abstract_action import AbstractAction
from ownline_core.core.exceptions import ActionExecutionException, MessageValidationException
from ownline_core.utils.cmd import execute_command


class PortForwardingAction(AbstractAction):
    """
    Class that executes iptables command to allow connections to LAN devices from a specific ip.
    Makes a new rule in the NAT table of the router to forward a port to a internal private ip
    Needs:
        - ip_src: the authorized IP from the connection will come
        - port_dst: the router port that will be forwarded to LAN
        - ip_dst_lan: internal LAN device ip
        - action: add or del a rule, flush all rules
    Optional:
        - duration: amount of time the NAT rule will be applied (default: 5 minutes)
        - port_dst_lan: internal LAN device port (default: same than port_dst)

    Command :
        iptables -t nat -I PREROUTING -s <ip_source>/32 -p tcp -m tcp --dport <port_src> -j DNAT --to-destination <ip_dst>:<port_dst>

    """

    def __init__(self, config=None, **kwargs):
        super().__init__(**kwargs)
        self.logger = logging.getLogger("ownline_core_log")
        self.config = config

    def initialize(self):
        self.logger.info("Initializing port forwarding")
        # Create custom iptables chain
        ok, stderr, stdout = execute_command([self.config.IPTABLES_BINARY, '-t', 'nat', '-N', self.config.PORT_FORWARDING_CHAIN], self.config.CONFIG_NAME)
        if not ok:
            self.logger.warning("Failed to create port forwarding chain: {}".format(stderr))

        # Flush all rules
        return self.do_flush()
    
    def do_add(self, trusted_ip, service, port_dst):
        ip_src = trusted_ip
        port_dst = str(port_dst)
        ip_dst_lan = service['ip_dst_lan']
        port_dst_lan = service['port_dst_lan']
        dst_lan = str(ip_dst_lan) + ':' + str(port_dst_lan)
        transport_protocol = service['transport_protocol']
        self.validate_transport_protocol(transport_protocol)

        cmd = [self.config.IPTABLES_BINARY, '-t', 'nat', '-A', self.config.PORT_FORWARDING_CHAIN,
               '-s', ip_src, '-p', transport_protocol, '-m', transport_protocol,
               '--dport', port_dst, '-j', 'DNAT', '--to-destination', dst_lan]

        ok, err, out = execute_command(cmd, self.config.CONFIG_NAME)

        if ok:
            self.logger.info("Inserted new port forwarding rule: {}".format(" ".join(cmd[1:])))
            return True
        else:
            raise ActionExecutionException("Failed adding execution: stderr: {} stout: {}".format(err, out))
    
    def do_del(self, session):
        ip_src = session['trusted_ip']
        port_dst = str(session['port_dst'])
        ip_dst_lan = session['service']['ip_dst_lan']
        port_dst_lan = session['service']['port_dst_lan']
        dst_lan = str(ip_dst_lan) + ':' + str(port_dst_lan)
        transport_protocol = session['service']['transport_protocol']
        self.validate_transport_protocol(transport_protocol)

        cmd = [self.config.IPTABLES_BINARY, '-t', 'nat', '-D', self.config.PORT_FORWARDING_CHAIN, '-s', ip_src, '-p',
               transport_protocol, '-m', transport_protocol,
               '--dport', str(port_dst), '-j', 'DNAT', '--to-destination', dst_lan]

        ok, err, out = execute_command(cmd, self.config.CONFIG_NAME)

        if ok:
            self.logger.info("Removed port forwarding rule: {}".format(" ".join(cmd[1:])))
            return True
        else:
            raise ActionExecutionException("Failed deleting execution: stderr: {} stout: {}".format(err, out))

    def do_flush(self):
        self.logger.info("Flushing all forwarding rules")
        ok, stderr, stdout = execute_command([self.config.IPTABLES_BINARY, '-t', 'nat', '-F', self.config.PORT_FORWARDING_CHAIN], self.config.CONFIG_NAME)
        if not ok:
            raise ActionExecutionException("Flush execution failed: {}".format(stderr))
        return True

    def validate_transport_protocol(self, transport_protocol):
        if transport_protocol not in self.config.ALLOWED_TRANSPORT_PROTOCOLS:
            raise MessageValidationException(f"Invalid transport_protocol service attribute: given {transport_protocol} but only allowed: {','.join(self.config.ALLOWED_TRANSPORT_PROTOCOLS)}")







