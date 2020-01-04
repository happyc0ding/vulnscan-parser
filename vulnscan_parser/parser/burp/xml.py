import logging
import re
from lxml import etree as elmtree
import os
from urllib.parse import urlparse
import base64
from html import unescape
from ipaddress import ip_address

from vulnscan_parser.parser.xml import VsXmlParser
from vulnscan_parser.models.burp.finding import BurpFinding
from vulnscan_parser.models.burp.host import BurpHost
from vulnscan_parser.models.burp.service import BurpService


LOGGER = logging.getLogger(__name__)


class BurpParserXML(VsXmlParser):

    # elements containing HTML
    ELM_HTML = (
        'issueBackground',
        'remediationBackground',
    )

    def __init__(self):
        super().__init__()
        # all parsed hosts
        self._hosts = {}
        # all parsed findings
        self._findings = {}
        # all parsed services
        self._services = {}
        # current finding
        self._curr_finding = None
        # regex for ugly/simple html parsing/removing
        self.tag_regex = re.compile('<.*?>')
        self.tag_content_regex = re.compile(r'<.*?>(.+?)</.*?>')
        self.tag_li_regex = re.compile(r'<li.*?>(.+?)</li>')

    @property
    def hosts(self):
        return self._hosts.copy()

    @property
    def findings(self):
        return self._findings.copy()

    @property
    def services(self):
        return self._services.copy()

    def clear_all_but_hosts(self):
        self._curr_filename = ''
        self._services.clear()
        self._findings.clear()

    def parse(self, filepath, huge_tree=False):
        LOGGER.info('Parsing file {}'.format(filepath))
        self._curr_filename = os.path.basename(filepath)
        self._curr_file_hash = self.hash_file(filepath)

        # noinspection PyBroadException
        try:
            for _, elm_issue in elmtree.iterparse(filepath, tag='issue', huge_tree=self.allow_huge_trees and huge_tree):
                finding = BurpFinding()
                # set current finding to new instance
                self._curr_finding = finding
                finding.src_file = self._curr_filename
                valid_ip = False

                for elm in elm_issue.getchildren():
                    content = elm.text
                    if elm.tag in self.ELM_HTML:
                        # remove tags
                        content = re.sub(self.tag_regex, '', content)
                        # replace html special chars
                        content = unescape(content)

                    if 'host' == elm.tag:
                        valid_ip = self.handle_host(elm.attrib['ip'], content)

                    elif elm.tag in ('references', 'vulnerabilityClassifications'):
                        self.handle_listings(elm, content)

                    elif 'requestresponse' == elm.tag:
                        self.handle_request_response(elm)

                    else:
                        if 'type' == elm.tag:
                            content = int(content)
                        # set attr dynamically
                        setattr(finding, elm.tag, content)

                if valid_ip:
                    id_hash = self.hash_sha1(
                        f'{finding.severity}-{finding.confidence}-{finding.path}-{finding.location}'.encode())
                    finding.id = f'{finding.ip}-{finding.hostname}-{finding.port}-{finding.type}-' \
                                 f'{finding.serialNumber}-{id_hash}'

                    if self._save_to_result_dict(self._findings, finding):
                        finding.host.findings.add(finding)
        except Exception:
            LOGGER.exception('Uncatched exception')

    def handle_host(self, ip, content):
        try:
            ip_address(ip)
        except ValueError:
            LOGGER.error(f'Not a valid ip address: {ip}. Will skip finding')
            return False
        finding = self._curr_finding
        # get existing host or create new
        try:
            host = self._hosts[ip]
        except KeyError:
            host = BurpHost()
            host.id = ip
            host.ip = ip
            self._hosts[ip] = host
        # add filename and add host to finding
        host.src_file.add(self._curr_filename)
        finding.host = host
        # parse url
        parsed_url = urlparse(content)
        finding.hostname = parsed_url.netloc
        # if we have a port
        if ':' in finding.hostname:
            finding.hostname, port = finding.hostname.split(':')
            # convert to int
            finding.port = int(port)
        # try to get port via protocol
        elif parsed_url.scheme.startswith('http'):
            finding.port = 80
            if parsed_url.scheme.endswith('s'):
                finding.port = 443
        # add hostname
        host.add_hostname(finding.hostname, 'unknown')
        # also create and add service
        s_id = f'{host.ip}-{finding.protocol}-{finding.port}'
        try:
            self._services[s_id]
        except KeyError:
            service = BurpService()
            service.id = s_id
            service.finding = finding
            service.host = host
            service.src_file = self._curr_filename
            self._services[s_id] = service

        return True

    def handle_listings(self, elm, content):
        finding = self._curr_finding
        for line in content.split('\n'):
            # dirty parsing
            matches = re.match(self.tag_li_regex, line)
            if matches:
                try:
                    entry = re.match(self.tag_content_regex, matches[1])[1]
                    getattr(finding, elm.tag).append(entry)
                except IndexError:
                    pass

    def handle_request_response(self, elm):
        finding = self._curr_finding
        for reqresp_child in elm.getchildren():
            data = reqresp_child.text
            # base64 decode if necessary
            try:
                if 'true' == reqresp_child.attrib['base64']:
                    try:
                        data = base64.b64decode(data).decode()
                    except UnicodeDecodeError:
                        data = '[vulnscan-parser]: Unable to decode content (probably binary)'
            except KeyError:
                pass
            if 'request' == reqresp_child.tag:
                finding.requestresponse['request_method'] = reqresp_child.attrib['method']
            finding.requestresponse[reqresp_child.tag] = data

    @classmethod
    def is_valid_file(cls, file):
        head = cls.get_file_head(file, 100)
        if head is None:
            LOGGER.error('Unable to read file: {}'.format(file))
            return False
        else:
            return len(head) > 1 and (head[0].startswith('<?xml') and any(['burpVersion' in line for line in head]))
