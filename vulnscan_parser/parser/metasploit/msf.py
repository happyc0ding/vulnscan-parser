import logging
from pprint import pprint
from collections import OrderedDict
import os
from itertools import islice
import json

from vulnscan_parser.parser.base import VSBaseParser
from vulnscan_parser.models.metasploit.host import MetasploitHost
from vulnscan_parser.models.metasploit.service import MetasploitService
# from vulnscan_parser.models.metasploit.finding import MetasploitFinding


LOGGER = logging.getLogger(__name__)


class MetasploitParser(VSBaseParser):

    ATTR_BLACKLIST = [
        'notes',
        'id',
    ]

    def __init__(self):
        super().__init__()
        self._hosts = {}
        self._services = {}
        self._findings = {}
        self._attr_blacklist = self.ATTR_BLACKLIST.copy()
        self.allowed_port_states = ['open']

    def add_get_host(self, address):
        try:
            host = self._hosts[address]
        except KeyError:
            host = MetasploitHost()
            host.ip = address
            host.id = address
            host.src_file = self._curr_filename
            self._hosts[address] = host

        return host

    def save_service(self, service, host):
        if service.state in self.allowed_port_states:
            service.id = '-'.join(
                map(str, (host.ip, service.proto, service.port, service.name, service.info)))
            if self._save_to_result_dict(self._services, service):
                service.host = host
                service.src_file = self._curr_filename
                host.services.add(service)
                return service

        return None

