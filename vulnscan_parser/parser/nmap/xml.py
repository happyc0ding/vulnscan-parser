import logging
from pprint import pprint
from collections import OrderedDict
import os
from itertools import islice

from libnmap.parser import NmapParser, NmapParserException, NmapReport
# try lxml, but use built-in as fallback
try:
    from lxml import etree as elmtree
except ImportError:
    from xml.etree import ElementTree as elmtree

from vulnscan_parser.parser.base import VSBaseParser
from vulnscan_parser.models.nmap.host import NmapHost
from vulnscan_parser.models.nmap.service import NmapService
from vulnscan_parser.models.nmap.finding import NmapFinding
from vulnscan_parser.models.nmap.certificate import NmapCertificate


LOGGER = logging.getLogger(__name__)


class NmapParserXML(VSBaseParser):

    def __init__(self):
        super().__init__()
        self._hosts = {}
        self._services = {}
        self._certificates = {}
        self._findings = {}
        self.allowed_port_states = ['open']

    def parse(self, filepath):
        if not self.is_valid_file(filepath):
            LOGGER.error('Ignoring invalid Nmap file: {}'.format(filepath))
            return
        LOGGER.info('Parsing file {})'.format(filepath))
        self._curr_filename = os.path.basename(filepath)
        self._curr_file_hash = self.hash_file(filepath)
        # noinspection PyBroadException
        try:
            self.libnmap_parse_xml_report(filepath)
        except Exception:
            LOGGER.exception('Error while parsing {}'.format(filepath))

    # "re-implement" parsing loop from libnmap, but use a saxparser instead. This is only a little bit faster than using
    # "parse_fromfile" directly, but saves *a lot* of memory.
    # it is also ugly, since i use private class methods directly
    def libnmap_parse_xml_report(self, filepath):
        # use recover=True in order to process cancelled scans (missing /nmaprun)
        for event, element in elmtree.iterparse(filepath, tag='host', recover=True):
            # don't care about the other stuff, i just need host and service info
            nmap_host = NmapParser._parse_xml_host(element)
            host = self._add_get_host(nmap_host.address, nmap_host.hostnames)
            for nmap_service in nmap_host.services:
                self._add_service(host, nmap_service)
            element.clear()

    def get_results(self):
        return self.hosts, self.findings, self.services, self.certificates, self.ciphers

    @property
    def hosts(self):
        return self._hosts.copy()

    @property
    def services(self):
        return self._services.copy()

    @property
    def certificates(self):
        return self._certificates.copy()

    @property
    def findings(self):
        return self._findings.copy()

    @property
    def ciphers(self):
        return {}

    def clear(self):
        self._hosts.clear()
        self._services.clear()
        self._certificates.clear()
        self._findings.clear()
        self._curr_filename = ''

    def _add_get_host(self, ip, hostnames):
        try:
            host = self._hosts[ip]
        except KeyError:
            host = NmapHost()
            # ip is named address in nmap
            host.address = ip
            host.id = host.address
            for hostname in hostnames:
                host.add_hostname(hostname, 'unknown')
            self._save_to_result_dict(self._hosts, host)

        return host

    def _add_service(self, host, nmap_service):
        if nmap_service.state not in self.allowed_port_states:
            return

        port = nmap_service.port
        protocol = nmap_service.protocol
        id_dict = nmap_service.service_dict.copy()
        try:
            # ignore fp for id
            id_dict.pop('servicefp')
        except KeyError:
            pass
        id_dict['name'] = nmap_service.service
        id_dict['ip'] = host.ip
        id_dict['protocol'] = protocol
        id_dict['port'] = port
        id_dict['script_num'] = len(nmap_service.scripts_results)

        service = NmapService()
        for key in nmap_service.service_dict:
            setattr(service, key, nmap_service.service_dict[key])
        # use sorted dict to assure order
        service.id = '-'.join([str(x) for x in OrderedDict(sorted(id_dict.items())).values()])
        service.name = nmap_service.service
        service.src_file = self._curr_filename
        service.protocol = protocol
        service.port = port
        # add service to host and vice versa
        service.host = host
        service.state = nmap_service.state

        if self._save_to_result_dict(self._services, service):
            host.services.add(service)
        else:
            try:
                # issue warning if fingerprint differs
                if service.servicefp != nmap_service.service_dict['servicefp']:
                    LOGGER.warning('Duplicate service, but fingerprint differs {}:{}/{}. Saved: "{}", ignored: {}'.
                                   format(host.ip, port, protocol, self._services[service.id].servicefp,
                                          nmap_service.service_dict['servicefp'])
                                   )
            except (AttributeError, KeyError):
                pass

        self._add_scripts(host, protocol, port, nmap_service.scripts_results)

    def _add_scripts(self, host, protocol, port, scripts_results):
        scripts_by_id = {}
        for sr in scripts_results:
            if sr['id'] not in scripts_by_id:
                scripts_by_id[sr['id']] = {}
            try:
                scripts_by_id[sr['id']]['output'] = sr['output']
            except KeyError:
                pass
            for k, v in sr['elements'].items():
                scripts_by_id[sr['id']][k] = v

        for script_id, data in scripts_by_id.items():
            finding = NmapFinding()
            finding.name = script_id
            finding.data = data
            finding.host = host
            finding.protocol = protocol
            finding.port = port
            finding.src_file = self._curr_filename
            finding.id = '{}-{}-{}-{}'.format(host.ip, port, protocol, finding.name)
            if self._save_to_result_dict(self._findings, finding):
                host.scripts.add(finding)

            if 'ssl-cert' == finding.name:
                self._add_certificate(host, protocol, port, data)

    def _add_certificate(self, host, protocol, port, data):
        cert = NmapCertificate()
        for k, v in data.items():
            setattr(cert, k, v)
        cert.host = host
        cert.protocol = protocol
        cert.port = port
        cert.src_file = self._curr_filename
        cert.id = '{}-{}-{}-{}'.format(host.ip, port, protocol, cert.sha1)
        if self._save_to_result_dict(self._certificates, cert):
            host.certificates.add(cert)

    @staticmethod
    def is_valid_file(file):
        try:
            with open(file, 'r') as file_handle:
                head = list(islice(file_handle, 5))

            return len(head) > 4 and head[0].startswith('<?xml') and any('nmaprun' in h for h in head)
        except:
            return False
