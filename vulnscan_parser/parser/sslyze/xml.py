import logging

from lxml import etree as elmtree
import os
from itertools import islice

from vulnscan_parser.parser.base import VSBaseParser
from vulnscan_parser.models.sslyze.finding import SslyzeFinding
from vulnscan_parser.models.sslyze.host import SslyzeHost
from vulnscan_parser.models.sslyze.cipher import SslyzeCipher
from vulnscan_parser.models.sslyze.vulnerability import SslyzeVulnerability
from vulnscan_parser.models.sslyze.certificate import SslyzeCertificate
from vulnscan_parser.models.sslyze.service import SslyzeService

LOGGER = logging.getLogger(__name__)


class SslyzeParserXML(VSBaseParser):

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
        try:
            for event, element in elmtree.iterparse(filepath, events=['end'], tag='target'):
                hostname = element.attrib['host']
                # create new host object
                try:
                    host = self._hosts[element.attrib['ip']]
                except KeyError:
                    host = SslyzeHost()
                    for name, value in element.attrib.items():
                        if name not in ('port', 'host'):
                            setattr(host, name, value)
                    host.ip = element.attrib['ip']
                    host.id = host.ip
                    self._save_to_result_dict(self._hosts, host)
                host.add_hostname(hostname, 'unknown')
                port = int(element.attrib['port'])
                service = SslyzeService()
                service.host = host
                service.port = port
                service.name = host.tlsWrappedProtocol
                service.id = '{}-{}-{}'.format(host.ip, port, service.name)
                self._save_to_result_dict(self._services, service)

                for target_child in element.getchildren():
                    if 'certinfo' == target_child.tag:
                        self._handle_certinfo(target_child, host, port, hostname)

                    elif (target_child.tag.startswith('ssl') or target_child.tag.startswith('tls')) and\
                            'isProtocolSupported' in target_child.attrib:
                        self._handle_protocol(target_child, host, port, hostname)

                    else:
                        self._handle_finding(target_child, host, port, hostname)
                # free memory
                element.clear()
        except:
            LOGGER.exception('Error while parsing {}'.format(filepath))
            self.parse_errors += 1

    def clear(self):
        self._hosts.clear()
        self._findings.clear()
        self._vulnerabilities.clear()
        self._ciphers.clear()
        self._services.clear()
        self._certificates.clear()
        self.parse_errors = 0

    def _handle_certinfo(self, certinfo_elm, host, port, hostname):
        vuln = self._get_create_vuln('ocspStapling', 'OSCP Stapling')
        self._create_finding(host, port, hostname, vuln, certinfo_elm.find('./ocspStapling').attrib)

        chain_elm = certinfo_elm.find('./receivedCertificateChain')
        vuln = self._get_create_vuln('certificateChain', 'VSCertificate chain info')
        self._create_finding(host, port, hostname, vuln, chain_elm.attrib)

        for cert_data in chain_elm.findall('./certificate'):
            cert = self._get_cert(cert_data)
            cert.host = host
            cert.port = port
            cert.hostname = hostname
            cert.id = '{}-{}-{}-{}'.format(host.ip, port, hostname, cert.hpkpSha256Pin)
            host.certificates.add(cert)

            if 'leaf' == cert.position:
                self._save_to_result_dict(self._certificates, cert)

        validation_elm = certinfo_elm.find('./certificateValidation')
        vuln = self._get_create_vuln('hostnameValidation', 'Hostname validation')
        self._create_finding(host, port, hostname, vuln, validation_elm.find('./hostnameValidation').attrib)

        path_validation = validation_elm.findall('./pathValidation')
        vuln = self._get_create_vuln('pathValidation', 'Path validation (trust store)')
        for path_val in path_validation:
            self._create_finding(host, port, hostname, vuln, path_val.attrib)

    def _get_cert(self, cert_data):
        cert = self._certelm_to_object(cert_data)
        for name, value in cert_data.attrib.items():
            setattr(cert, name, value)

        return cert

    def _handle_protocol(self, protocol_elm, host, port, hostname):
        vuln = self._get_create_vuln(protocol_elm.tag, protocol_elm.attrib['title'])
        self._create_finding(host, port, hostname, vuln, protocol_elm.attrib)
        host.preferred_ciphers.extend(self._get_ciphers(protocol_elm, './preferredCipherSuite/cipherSuite',
                                                        host, port, hostname))
        accepted_ciphers = self._get_ciphers(protocol_elm, './acceptedCipherSuites/cipherSuite',
                                                       host, port, hostname)
        host.accepted_ciphers.extend(accepted_ciphers)

        for c in accepted_ciphers:
            self._save_to_result_dict(self._ciphers, c)

    def _get_ciphers(self, protocol_elm, cipher_path, host, port, hostname):
        ciphers = []
        for cipher_data in protocol_elm.findall(cipher_path):
            cipher = SslyzeCipher()
            cipher.host = host
            cipher.port = port
            cipher.hostname = hostname
            cipher.tls_protocol = protocol_elm.tag
            for name, value in self._attr_to_dict(cipher_data).items():
                setattr(cipher, name, value)
            key_exchange = cipher_data.find('./keyExchange')
            if key_exchange is not None:
                cipher.keyExchange = self._attr_to_dict(key_exchange)
            cipher.src_file = self._curr_filename
            cipher.id = '{}-{}-{}-{}-{}'.format(host.ip, port, hostname, cipher.tls_protocol, cipher.name)

            ciphers.append(cipher)

        return ciphers

    def _handle_finding(self, vuln_elm, host, port, hostname):
        title = ''
        try:
            title = vuln_elm.attrib['title']
        except KeyError:
            pass
        try:
            exc = vuln_elm.attrib['exception']
            LOGGER.warning('Exception while trying to determine finding {}: {}'.format(
                vuln_elm.tag, exc))
        except KeyError:
            pass
        vuln = self._get_create_vuln(vuln_elm.tag, title)
        attrs = {}
        for finding_child in vuln_elm.getchildren():
            attrs[finding_child.tag] = self._attr_to_dict(finding_child.attrib)
        self._create_finding(host, port, hostname, vuln, attrs)

    def _get_create_vuln(self, vuln_name, title):
        try:
            vuln = self._vulnerabilities[vuln_name]
        except KeyError:
            vuln = SslyzeVulnerability()
            vuln.name = vuln_name
            vuln.title = title
            self._vulnerabilities[vuln_name] = vuln

        return vuln

    def _create_finding(self, host, port, hostname, vuln, attrs):
        # create finding identifier
        finding_id = '{}-{}-{}-{}'.format(host.ip, port, hostname, vuln.name)
        if 'pathValidation' == vuln.name:
            finding_id = '{}-{}'.format(finding_id, attrs['usingTrustStore'])

        # create finding object
        finding = SslyzeFinding()
        finding.id = finding_id
        finding.vulnerability = vuln
        finding.port = port
        finding.host = host
        finding.hostname = hostname
        finding.src_file = self._curr_filename
        vuln.findings.add(finding)

        # set attributes form xml as object attributes
        for k, v in attrs.items():
            setattr(finding, k, v)

        # also append to host, if finding is saved
        if self._save_to_result_dict(self._findings, finding):
            host.findings.add(finding)

    @staticmethod
    def _attr_to_dict(attr):
        return dict(attr.items())

    @staticmethod
    def _certelm_to_object(cert):
        result = SslyzeCertificate()
        for name, value in cert.attrib.items():
            setattr(result, name, value)
        SslyzeParserXML._cert_to_attr(result, cert)

        return result

    @staticmethod
    def _cert_to_attr(obj, elm):
        if len(elm.getchildren()) > 0:
            for child in elm.getchildren():
                # recursion
                setattr(obj, elm.tag, SslyzeParserXML._cert_to_attr(obj, child))
        else:
            setattr(obj, elm.tag, elm.text)

    @staticmethod
    def is_valid_file(file):
        head = VSBaseParser.get_file_head(file, 2)
        if head is None:
            LOGGER.error('Unable to read file: {}'.format(file))
            return False
        else:
            return len(head) > 1 and head[0].startswith('<?xml') and 'sslyze' in head[1].lower()
