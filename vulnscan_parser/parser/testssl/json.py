import logging
import json
import os
import re
from datetime import datetime

from vulnscan_parser.parser.base import VSBaseParser
from vulnscan_parser.models.testssl.finding import TestsslFinding
from vulnscan_parser.models.testssl.host import TestsslHost
from vulnscan_parser.models.testssl.vulnerability import TestsslVulnerability
from vulnscan_parser.models.testssl.cipher import TestsslCipher
from vulnscan_parser.models.testssl.certificate import TestsslCertificate
from vulnscan_parser.models.testssl.service import TestsslService

LOGGER = logging.getLogger(__name__)


class TestsslParserJson(VSBaseParser):

    # these attributes will be set in the vulnerability (aside from the vuln name)
    # also, they will be mapped to lists
    VULN_ATTRS = [
        'cve',
        'cwe',
    ]

    CERT_NUM_REGEX = re.compile('<cert#(\d)>')

    def __init__(self):
        super().__init__()
        self._hosts = {}
        self._vulnerabilities = {}
        self._findings = {}
        self._certificates = {}
        self._services = {}
        self._ciphers = {}
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
        try:
            LOGGER.info('Parsing file {}'.format(filepath))
            self._curr_filename = os.path.basename(filepath)
            self._curr_file_hash = self.hash_file(filepath)

            invalid_file = True
            with open(filepath, 'r') as handle:
                json_data = json.load(handle)
                try:
                    if all(x in json_data[0] for x in ('id', 'ip', 'port', 'severity', 'finding')):
                        invalid_file = False
                        self.parse_normal(json_data)
                except KeyError:
                    try:
                        if 'testssl' in json_data['Invocation']:
                            invalid_file = False
                    except KeyError:
                        pass
                    if not invalid_file:
                        self.parse_pretty(json_data)

            if invalid_file:
                LOGGER.warning('Not a testssl file: {}'.format(filepath))

        except json.decoder.JSONDecodeError:
            LOGGER.exception('JSON error while decoding {}. File ignored'.format(filepath))
            self.parse_errors += 1
        except:
            LOGGER.exception('Exception while handling {}'.format(filepath))

    def parse_pretty(self, json_data):
        scan_result = json_data['scanResult']
        for sr in scan_result:
            ip = sr['ip']
            hostname = sr['targetHost']
            port = int(sr['port'])
            host = self._add_get_host(ip, hostname)
            self._add_service(host, port, sr['service'])

            for rkey in ('protocols', 'ciphers', 'serverPreferences', 'serverDefaults',
                         'vulnerabilities', 'cipherTests'):
                for entry in sr[rkey]:
                    self._handle_finding(host, port, hostname, entry)

    def parse_normal(self, json_data):
        for entry in json_data:
            hostname, ip = entry['ip'].split('/')
            port = int(entry['port'])
            if hostname == ip:
                hostname = ''

            if not (ip and port):
                if 'engine_problem' == entry['id']:
                    LOGGER.warning('Seems there were errors during the execution of testssl.'
                                   ' Please check manually.')
                else:
                    LOGGER.warning('Invalid entry (no ip/port): {}'.format(entry))
                continue

            host = self._add_get_host(ip, hostname)
            self._handle_finding(host, port, hostname, entry)

    def _add_get_host(self, ip, hostname):
        try:
            host = self._hosts[ip]
        except KeyError:
            host = TestsslHost()
            host.ip = ip
            host.id = ip
            self._hosts[ip] = host
        if hostname:
            host.add_hostname(hostname, 'unknown')
        host.src_file.add(self._curr_filename)

        return host

    def clear(self):
        self._hosts.clear()
        self._findings.clear()
        self._vulnerabilities.clear()
        self._ciphers.clear()
        self._certificates.clear()
        self._services.clear()
        self.parse_errors = 0

    def _handle_finding(self, host, port, hostname, entry):
        vuln_name = entry['id'].lower()

        # do not treat service, scantime etc. as a finding (like in pretty format)
        if 'service' == vuln_name:
            self._add_service(host, port, entry['finding'])
            return
        elif 'scantime' == vuln_name:
            return

        try:
            vuln = self._vulnerabilities[vuln_name]
        except KeyError:
            vuln = TestsslVulnerability()
            vuln.name = vuln_name
            for key in self.VULN_ATTRS:
                try:
                    setattr(vuln, key, entry[key].split(' '))
                except KeyError:
                    pass
            self._vulnerabilities[vuln_name] = vuln

        # create finding
        finding = TestsslFinding()
        finding.src_file = self._curr_filename
        # set data
        # there are duplicate "id" entries, i.e. for DROWN -> hash "finding"
        finding.id = '-'.join(map(str,
                                  (host.ip, port, hostname, entry['id'], self.hash_sha1(entry['finding'].encode()))))
        finding.port = port
        finding.host = host
        finding.hostname = hostname
        finding.finding = entry['finding']
        finding.severity = entry['severity']
        finding.vulnerability = vuln

        for key in self.VULN_ATTRS:
            try:
                # make sure the values are the same for all findings (will overwrite if differs from vuln)
                setattr(finding, key, entry[key].split(' '))
            except KeyError:
                pass

        if entry['id'].startswith('cipher-'):
            self._handle_cipher(finding)
        elif entry['id'].startswith('cert') or 'OCSP' in entry['id']:
            cert_num = 1
            try:
                cert_num = self.CERT_NUM_REGEX.findall(entry['id'])[0]
            except IndexError:
                pass
            self._handle_certificate(finding, cert_num)

        if self._save_to_result_dict(self._findings, finding):
            host.findings.add(finding)
            vuln.findings.add(finding)
            vuln.hosts.add(host)

    def _handle_certificate(self, finding, cert_num):
        cert_id = '{}-{}-{}-{}'.format(finding.host.ip, finding.port, finding.hostname, cert_num)
        try:
            cert = self._certificates[cert_id]
        except KeyError:
            cert = TestsslCertificate()
            cert.id = cert_id
            cert.finding = finding
            cert.src_file = self._curr_filename
            self._certificates[cert.id] = cert

        # property name, i.e. "cert_serialNumber" or "cert_serialNumber <cert#1>"
        prop_name = finding.vulnerability.name
        # remove cert number for attributes
        num_index = prop_name.find(' <')
        if num_index > -1:
            prop_name = prop_name[:num_index]
        # cert is already known, but the new property differs from the known one
        if hasattr(cert, prop_name) and getattr(cert, prop_name) != finding.finding:
            LOGGER.warning('VSCertificate ({}) property already set: "{}". First one takes precedence'.format(
                cert.id, prop_name))
        else:
            if prop_name.startswith('cert_notafter') or prop_name.startswith('cert_notbefore'):
                setattr(cert, prop_name, datetime.strptime(finding.finding, '%Y-%m-%d %H:%M'))
            else:
                setattr(cert, prop_name, finding.finding)
                if prop_name.startswith('cert_keysize'):
                    algo, bits, _ = finding.finding.split(' ')
                    cert.m_public_key_algorithm = algo
                    cert.m_public_key_len = int(bits)

    def _handle_cipher(self, finding):
        cipher = TestsslCipher()
        cipher.src_file = self._curr_filename
        cipher.protocol = finding.protocol
        cipher.port = finding.port
        cipher.hostname = finding.hostname
        # TODO
        cipher.host = finding.host

        # TODO: parsing cipher output sucks!
        # TODO: use pyparsing instead?
        # TODO: use openssl definitions instead? -> openssl ciphers -V ALL
        # -> use testssl's openssl to generate an initial cipher list and run the above cmd on invocation in order
        # to detect potential new ciphers
        # sample lines:
        # TLS 1.2   xc012   ECDHE-RSA-DES-CBC3-SHA            ECDH 256   3DES      168      TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
        # TLS 1   xc014   ECDHE-RSA-AES256-SHA              ECDH 256   AES       256      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        # TLS 1   x2f     AES128-SHA                        RSA        AES       128      TLS_RSA_WITH_AES_128_CBC_SHA
        # SSLv3   x35     AES256-SHA                     RSA        AES        256         TLS_RSA_WITH_AES_256_CBC_SHA
        # TLS 1.2   x010080 RC4-MD5                        RSA        RC4        128         SSL_CK_RC4_128_WITH_MD5
        # TLS 1   x41     CAMELLIA128-SHA                   RSA        Camellia    128      TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
        # TLS 1.2   xc07a   -                                 RSA        CamelliaGCM 128      TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256

        output = finding.finding
        # first 2 spaces separate protocol from cipher hexcode
        first_two_spaces = output.find('  ')
        # find beginning of cipher hexcode (might be only separated by 1 space)
        index = output.find(' ', first_two_spaces + 3)
        # TODO: thix fixes output for "CamelliaGCM" which is only separated by 1 space from key size, see:
        # TLS 1.2   xc07a   -                                 RSA        CamelliaGCM 128      TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256
        output = output.replace('CamelliaGCM ', 'CamelliaGCM  ')
        # parse the rest by 2-space separator
        data = self._parse_by_sep(output[index + 1:], '  ')
        proto = output[:first_two_spaces].strip(' ')
        name = data[0]
        key_exchange = data[1].split(' ')
        if '(' in key_exchange[0]:
            # i.e. "DH(512)"
            key_exchange = key_exchange[0][:-1].split('(')
        bits = data[3]

        cipher.name = name
        cipher.tls_protocol = proto
        cipher.key_exchange_algorithm = key_exchange[0]
        try:
            cipher.key_exchange_bits = int(key_exchange[1])
        except (KeyError, IndexError):
            cipher.key_exchange_bits = 0
        # bit size may contain values like '56,exp', but also 'None'
        key_size = bits.split(',')[0]
        if 'None' == key_size:
            key_size = 0
        cipher.key_size = int(key_size)
        cipher.id = '-'.join([finding.host.ip, str(finding.port), finding.hostname, finding.vulnerability.name])

        return self._save_to_result_dict(self._ciphers, cipher)

    def _add_service(self, host, port, name):
        service = TestsslService()
        service.host = host
        service.port = port
        if 'Couldn\'t determine service' not in name:
            service.name = name.replace('Service detected: ', '')
        service.id = '{}-{}-{}'.format(host.ip, port, service.name)
        service.src_file = self._curr_filename
        if self._save_to_result_dict(self._services, service):
            host.services.add(service)

    @staticmethod
    def is_valid_file(file):
        head = VSBaseParser.get_file_head(file, 16)
        if head is None:
            LOGGER.error('Unable to read file: {}'.format(file))
            return False
        else:
            return len(head) > 2 and\
                ((head[0].startswith('[') and all(x in head[2].lower() for x in ('id', ':', '"')))
                 or (head[0].startswith('{') and
                     any(all(x in h.lower() for x in ('invocation', 'testssl')) for h in head)))

    @staticmethod
    def _parse_by_sep(line, sep):
        data = line.split(sep)
        # filter empty entries and strip spaces
        return [x.strip(' ') for x in data if x]
