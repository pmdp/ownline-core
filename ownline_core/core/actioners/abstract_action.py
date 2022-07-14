from abc import ABC, abstractmethod


class AbstractAction(ABC):

    def do_update(self, update_request):
        update_request['ip_src'] = update_request['session']['ip_src']
        if self.do_del(update_request):
            if self.do_add({'ip_src': update_request['new_ip_src'], 'service': update_request['service']}):
                return True
            # else raise an exception that is catched at do_action

    @abstractmethod
    def do_add(self, trusted_ip, service, port_dst):
        return

    @abstractmethod
    def do_del(self, session):
        return

    @abstractmethod
    def do_flush(self):
        return
