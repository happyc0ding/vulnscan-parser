import logging
import os
import re
from ipaddress import ip_address

import OpenSSL.crypto

from vulnscan_parser.parser.base import VSBaseParser
from vulnscan_parser.models.pem.host import PemHost
from vulnscan_parser.models.pem.certificate import PemCertificate
from vulnscan_parser.models.pem.service import PemService

LOGGER = logging.getLogger(__name__)


class PemParserText(VSBaseParser):

    CERT_REGEX = re.compile(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', flags=re.DOTALL)

    def __init__(self):
        super().__init__()
        self._hosts = {}
        self._services = {}
        self._certificates = {}

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
        return {}

    @property
    def ciphers(self):
        return {}

    def clear(self):
        self._hosts.clear()
        self._services.clear()
        self._certificates.clear()
        self._curr_filename = ''
        self._curr_file_hash = ''

    def parse(self, filepath):
        try:
            LOGGER.info('Parsing file {}'.format(filepath))
            self._curr_filename = os.path.basename(filepath)
            # i.e.:
            # openssl_ip-TCP-443.pem
            # 1.2.3.4-TCP-443-hostname.de.pem
            hostname = ''
            base_name = os.path.basename(filepath)
            tool_name = base_name[0:base_name.find('_')]
            # remove prefix and extension
            ip_proto_port_hostname = base_name[len(tool_name)+1:].rsplit('.', 1)[0]
            ip = ip_proto_port_hostname.split('-')[0]
            # will raise an exception if incorrect ip
            ip_address(ip)
            hn_proto_port = ip_proto_port_hostname[len(ip)+1:]

            pph = hn_proto_port.split('-', 1)
            proto, port_num_x = pph
            # hostname in filename
            if '-' in port_num_x:
                port, hostname = port_num_x.split('-', 1)
            else:
                port = port_num_x
            port = int(port)
        except:
            LOGGER.error('Error while determining ip/hostname/port from filename')
            return
        try:
            self._read_cert(ip, hostname, proto, port, filepath)
        except:
            LOGGER.exception('Error while handling certificate')

    def _read_cert(self, ip, hostname, protocol, port, filepath):
        try:
            host = self._hosts[ip]
        except KeyError:
            host = PemHost()
            host.id = ip
            host.ip = ip
            self._hosts[ip] = host
        host.src_file.add(self._curr_filename)
        if hostname:
            host.add_hostname(hostname, 'unknown')

        service_id = '{}-{}-{}'.format(ip, protocol, port)
        try:
            service = self._services[service_id]
        except KeyError:
            service = PemService()
            service.id = service_id
            service.host = host
            service.protocol = protocol
            service.port = port
            host.services.add(service)
            self._services[service_id] = service

        x509_cert = None
        pem = None

        with open(filepath, 'r') as the_file:
            file_content = the_file.read()
            data = self.CERT_REGEX.findall(file_content)

            if len(data) > 0:
                pem = data[0]
                # hash pem part only for this one, hashing the complete output does not make sense due to timestamps
                self._curr_file_hash = self.hash_data(pem)
                x509_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem.encode())
            else:
                LOGGER.error('Could not get certificate data from file "{}"'.format(filepath))

        if x509_cert:
            cert_id = '-'.join(map(str, (ip, port, protocol, hostname, self._curr_file_hash)))

            try:
                self._certificates[cert_id]
            except KeyError:
                cert = PemCertificate()
                self._certificates[cert_id] = cert
                cert.id = cert_id
                cert.host = host
                cert.service = service
                cert.hostname = hostname

                # remove BEGIN/END certificate markers
                cert.pem = ''.join(pem.split('\n')[1:-1])
                cert.__dict__.update(self.pem_to_dict(x509_cert, filepath))

    @staticmethod
    def is_valid_file(file):
        head = VSBaseParser.get_file_head(file, 1)
        if head is None:
            LOGGER.error('Unable to read file: {}'.format(file))
            return False
        else:
            return len(head) > 0 and head[0].startswith('CONNECTED')
