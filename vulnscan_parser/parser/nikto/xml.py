import logging
from pprint import pprint
from collections import OrderedDict
import os
from itertools import islice

# try lxml, but use built-in as fallback
try:
    from lxml import etree as elmtree
except ImportError:
    from xml.etree import ElementTree as elmtree

from vulnscan_parser.parser.xml import VsXmlParser
from vulnscan_parser.models.nikto.host import NiktoHost
from vulnscan_parser.models.nikto.service import NiktoService
from vulnscan_parser.models.nikto.finding import NiktoFinding
from vulnscan_parser.models.nikto.vulnerability import NiktoVulnerability


LOGGER = logging.getLogger(__name__)


class NiktoParserXML(VsXmlParser):

    ATTR_BLACKLIST = [
        'notes',
        'host-id'
    ]

    def __init__(self):
        super().__init__()
        self._hosts = {}
        self._services = {}
        self._findings = {}
        self._vulnerabilities = {}

    def parse(self, filepath, huge_tree=False):
        if huge_tree and not self.allow_huge_trees:
            LOGGER.warning('Trying to parse with huge_tree=True, but is disabled globally')
            huge_tree = False
        self._curr_filename = os.path.basename(filepath)
        self._curr_file_hash = self.hash_file(filepath)

        for event, scandetail_elm in elmtree.iterparse(
                filepath, tag='scandetails', events=['start'], huge_tree=huge_tree):
            ip = scandetail_elm.attrib['targetip']
            hostname = scandetail_elm.attrib['targethostname']
            if ip == hostname:
                hostname = ''
            port = int(scandetail_elm.attrib['targetport'])
            banner = scandetail_elm.attrib['targetbanner']
            host = self.add_get_host(ip, hostname)
            service = self.add_get_service(port, banner, host)

            for item_elm in scandetail_elm.iterchildren(tag='item'):
                item_id = item_elm.attrib['id']
                osvdb_id = item_elm.attrib['osvdbid']
                vuln = self.add_get_vuln(item_id, osvdb_id)

                finding = NiktoFinding()
                for finding_attr_elm in item_elm.iterchildren():
                    setattr(finding, finding_attr_elm.tag, finding_attr_elm.text)
                finding.id = '-'.join(map(str, (ip, hostname, port, item_id)))
                if self._save_to_result_dict(self._findings, finding):
                    finding.src_file = self._curr_filename
                    finding.vulnerability = vuln
                    finding.host = host
                    finding.hostname = hostname
                    finding.port = port

                    host.findings.add(finding)
                    vuln.findings.add(finding)

    def add_get_vuln(self, vulnid, osvdbid):
        try:
            vuln = self._vulnerabilities[vulnid]
        except KeyError:
            vuln = NiktoVulnerability()
            vuln.id = vulnid
            vuln.osvdbid = osvdbid
            self._vulnerabilities[vulnid] = vuln

        return vuln

    def add_get_service(self, port, banner, host):
        service_id = '-'.join(map(str, (host.ip, port, banner)))
        try:
            service = self._services[service_id]
        except KeyError:
            service = NiktoService()
            service.id = service_id
            service.host = host
            service.port = port
            service.banner = banner
            service.src_file = self._curr_filename
            if self._save_to_result_dict(self._services, service):
                host.services.add(service)

        return service

    def add_get_host(self, ip, hostname):
        try:
            host = self._hosts[ip]
        except KeyError:
            host = NiktoHost()
            host.ip = ip
            host.id = ip
            host.src_file = self._curr_filename
            self._hosts[ip] = host
        host.add_hostname(hostname, '')

        return host
