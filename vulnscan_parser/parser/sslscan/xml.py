import logging
from datetime import datetime, timezone
from itertools import islice
import os
from ipaddress import ip_address

LOGGER = logging.getLogger(__name__)


from lxml import etree
from lxml.etree import ParseError as ParseError

from vulnscan_parser.parser.base import VSBaseParser
from vulnscan_parser.models.sslscan.finding import SslscanFinding
from vulnscan_parser.models.sslscan.host import SslscanHost
from vulnscan_parser.models.sslscan.cipher import SslscanCipher
from vulnscan_parser.models.sslscan.vulnerability import SslscanVulnerability
from vulnscan_parser.models.sslscan.certificate import SslscanCertificate
from vulnscan_parser.models.sslscan.service import SslscanService


class SSLScanParserXML(VSBaseParser):

    def __init__(self):
        super().__init__()
        self._hosts = {}
        self._vulnerabilities = {}
        self._findings = {}
        self._ciphers = {}
        self._services = {}
        self._certificates = {}
        self.parse_errors = 0

    def get_results(self):
        return self.hosts, self.findings, self.services, self.certificates, self.ciphers

    @property
    def hosts(self):
        return self._hosts.copy()

    @property
    def findings(self):
        return self._findings.copy()

    @property
    def vulnerabilities(self):
        return self._vulnerabilities.copy()

    @property
    def ciphers(self):
        return self._ciphers.copy()

    @property
    def certificates(self):
        return self._certificates.copy()

    @property
    def services(self):
        return self._services.copy()

    def parse(self, filepath):
        LOGGER.info('Parsing file {})'.format(filepath))
        self._curr_filename = os.path.basename(filepath)
        self._curr_file_hash = self.hash_file(filepath)

        host = None
        certificate = None

        # using flags and iterative parsing seems a little over the top, however the sslscan xml structure is
        # easy enough to handle this quickly and efficiently
        for event, element in etree.iterparse(filepath, events=('start', 'end')):
            if 'start' == event:
                if 'ssltest' == element.tag:
                    ip = element.attrib['host']
                    try:
                        ip_address(ip)
                        hostname = element.attrib['sniname']
                    except (KeyError, ValueError):
                        LOGGER.error('Invalid sslscan format!'
                                     ' Use "--sni-name=" in order to create reasonable xml files')
                        break

                    port = int(element.attrib['port'])
                    if ip == hostname:
                        hostname = ''

                    if not (ip and port):
                        LOGGER.warning('Missing a critical value, findings for '
                                       'ip: {} with hostname: {} on port {} ignored!'.format(ip, hostname, port))
                    else:
                        try:
                            host = self._hosts[ip]
                        except KeyError:
                            host = SslscanHost()
                            host.ip = ip
                            host.id = ip
                            host.add_hostname(hostname, 'unknown')
                            self._save_to_result_dict(self._hosts, host)

                        service_id = '{}-{}'.format(host.ip, port)
                        try:
                            self._services[service_id]
                        except KeyError:
                            service = SslscanService()
                            service.protocol = 'TCP'
                            service.port = port
                            service.id = service_id
                            self._save_to_result_dict(self._services, service)

                elif host is not None:
                    if 'cipher' == element.tag:
                        cipher = SslscanCipher()
                        cipher.key_size = int(element.attrib['bits'])
                        cipher.name = element.attrib['cipher']
                        cipher.proto = element.attrib['sslversion']
                        self._save_to_result_dict(self._ciphers, cipher)
                    elif 'certificate' == element.tag:
                        certificate = SslscanCertificate()
                        certificate.port = port
                        certificate.hostname = hostname
                        certificate.host = host
                        certificate.protocol = 'TCP'

                    else:
                        for attr in ('supported', 'vulnerable'):
                            try:
                                if '1' == element.attrib[attr] and \
                                        ('renegotiation' != element.tag or '1' != element.attrib['secure']):
                                        self._get_create_finding(host, port, hostname, element.tag)
                            except KeyError:
                                pass

            elif 'end' == event:
                if host is not None:
                    if 'ssltest' == element.tag:
                        host = None
                    elif 'certificate' == element.tag:
                        certificate.id = '{}-{}-{}'.format(host.ip, port, hostname)
                        self._save_to_result_dict(self._certificates, certificate)
                        certificate = None

                    if certificate is not None:
                        if 'signature-algorithm' == element.tag:
                            certificate.signature_algorithm = element.text
                        elif 'pk' == element.tag:
                            certificate.pubkey_size = int(element.attrib['bits'])
                        elif 'subject' == element.tag:
                            certificate.subject['CN'] = element.text
                        elif 'altnames' == element.tag:
                            alt_names = element.text.replace('DNS:', '')
                            if ',' in alt_names:
                                alt_names = alt_names.split(',')
                            else:
                                alt_names = [alt_names]

                            for alt_name in alt_names:
                                certificate.altnames.append(alt_name.strip(' '))
                        elif 'not-valid-after' == element.tag:
                            certificate.not_after = datetime.strptime(
                                element.text, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                            # TODO: experimental
                            certificate.not_after = certificate.not_after.astimezone(timezone.utc)
                        elif 'not-valid-before' == element.tag:
                            certificate.not_before = datetime.strptime(
                                element.text, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                            # TODO: experimental
                            certificate.not_before = certificate.not_before.astimezone(timezone.utc)

                        elif 'self-signed' == element.tag and 'true' == element.text:
                            self._get_create_finding(host, port, hostname, 'selfsignedcert')
                        elif 'expired' == element.tag and 'true' == element.text:
                            self._get_create_finding(host, port, hostname, 'expiredcert')

                element.clear()

    def _get_create_vuln(self, name):
        try:
            vuln = self._vulnerabilities[name]
        except KeyError:
            vuln = SslscanVulnerability()
            vuln.name = name
            self._vulnerabilities[name] = vuln

        return vuln

    def _get_create_finding(self, host, port, hostname, vuln_name):
        vuln = self._get_create_vuln(vuln_name)
        finding_id = '{}-{}-{}-{}'.format(host.ip, port, hostname, vuln.name)
        finding = SslscanFinding()
        finding.id = finding_id
        finding.vulnerability = vuln
        finding.port = port
        finding.host = host
        finding.hostname = hostname
        finding.src_file = self._curr_filename
        vuln.findings.add(finding)
        host.findings.add(finding)

        self._save_to_result_dict(self._findings, finding)

        return finding

    def clear(self):
        self._hosts.clear()
        self._findings.clear()
        self._vulnerabilities.clear()
        self._ciphers.clear()
        self._certificates.clear()
        self._services.clear()
        self.parse_errors = 0


    @staticmethod
    def is_valid_file(file):
        head = VSBaseParser.get_file_head(file, 2)
        if head is None:
            LOGGER.error('Unable to read file: {}'.format(file))
            return False
        else:
            return len(head) > 1 and head[0].startswith('<?xml') and\
                head[1].startswith('<document title="SSLScan Results"') and 'rbsec' in head[1]
