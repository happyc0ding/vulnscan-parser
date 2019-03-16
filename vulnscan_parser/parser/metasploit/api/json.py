import logging
from pprint import pprint
from collections import OrderedDict
import os
from itertools import islice
import json

from vulnscan_parser.parser.metasploit.msf import MetasploitParser
from vulnscan_parser.models.metasploit.service import MetasploitService
from vulnscan_parser.models.metasploit.credentials import MetasploitCredentials
#from vulnscan_parser.models.metasploit.finding import MetasploitFinding


LOGGER = logging.getLogger(__name__)


class MetasploitParserJson(MetasploitParser):

    def __init__(self):
        super().__init__()
        self._credentials = {}

    def parse(self, filepath):
        LOGGER.info('Parsing file {}'.format(filepath))
        self._curr_filename = os.path.basename(filepath)
        self._curr_file_hash = self.hash_file(filepath)

        # noinspection PyBroadException
        try:
            with open(filepath, 'r') as handle:
                json_data = json.load(handle)

            data = json_data['data']
            is_service_file = False
            is_creds_file = False
            try:
                # check for services
                # noinspection PyStatementEffect
                data[0]['host_id']
                is_service_file = True
            except KeyError:
                pass
            try:
                # noinspection PyStatementEffect
                'Metasploit::Credential' in data[0]['origin_type']
                is_creds_file = True
            except KeyError:
                pass

            if is_service_file:
                self.parse_services(data)
            elif is_creds_file:
                self.parse_credentials(data)
            else:
                LOGGER.warning('Unknown file format in {}'.format(filepath))
        except Exception:
            LOGGER.exception('Error while parsing file')

    def parse_services(self, data):
        for parsed_service in data:
            service = MetasploitService()
            service.service_id = parsed_service['id']
            host = None
            for key, value in parsed_service.items():
                if 'host' == key:
                    address = value['address']
                    host = self.add_get_host(address)
                    host.host_id = value['id']
                    for host_key, host_value in value.items():
                        if host_key in self._attr_blacklist:
                            continue
                        setattr(host, host_key, host_value)
                else:
                    setattr(service, key, value)
            if host:
                self.save_service(service, host)

    def parse_credentials(self, data):
        for parsed_creds in data:
            creds = MetasploitCredentials()
            creds.username = parsed_creds['public']['username']
            creds.password = parsed_creds['private']['data']
            creds.jtr_format = parsed_creds['private']['jtr_format']
            creds.realm = (parsed_creds['realm']['key'], parsed_creds['realm']['value'])
            creds.origin = parsed_creds['origin']['filename']
            creds.id = self.hash_sha1(''.join(
                map(str, (creds.username, creds.password, creds.realm[0], creds.realm[1], creds.origin))))
            self._save_to_result_dict(self._credentials, creds)
