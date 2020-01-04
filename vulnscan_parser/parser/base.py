import logging
import hashlib
from datetime import datetime
from itertools import islice

from vulnscan_parser.models.dotdict import DotDict


LOGGER = logging.getLogger(__name__)


class VSBaseParser(object):

    HASH_BUFFER_SIZE = 8192
    CERT_DATE_PATTERN = '%Y%m%d%H%M%SZ'

    def __init__(self):
        super().__init__()
        self._curr_filename = ''
        self._curr_file_hash = ''
        # set this flag if you want to ignore duplicate findings
        self.add_duplicates = True

    @property
    def hosts(self):
        return {}

    @property
    def plugins(self):
        return {}

    @property
    def findings(self):
        return {}

    @property
    def certificates(self):
        return {}

    @property
    def ciphers(self):
        return {}

    @property
    def services(self):
        return {}

    def _save_to_result_dict(self, result_dict, _object):
        is_saved = False
        if self.add_duplicates:
            # add file hash to id, ignore this kind of duplicate (parsing the exact same file twice)
            if not _object.id.endswith(self._curr_file_hash):
                _object.id = self.create_uid(_object.id)
        try:
            # do not overwrite existing results
            result_dict[_object.id]
        except KeyError:
            # save to list
            result_dict[_object.id] = _object
            is_saved = True

        return is_saved

    @staticmethod
    def hash_sha1(data):
        hashsum = hashlib.sha1()
        hashsum.update(data)

        return hashsum.hexdigest()

    def hash_file(self, filepath):
        hashsum = hashlib.sha1()
        with open(filepath, 'rb') as the_file:
            data = the_file.read(self.HASH_BUFFER_SIZE)
            while data:
                hashsum.update(data)
                data = the_file.read(self.HASH_BUFFER_SIZE)
        return hashsum.hexdigest()

    def hash_data(self, data):
        hashsum = hashlib.sha1()
        hashsum.update(data.encode())
        return hashsum.hexdigest()

    @staticmethod
    def _get_cert_components(components):
        # 0=key, 1=value
        return {comp[0].decode(): comp[1].decode() for comp in components}

    def pem_to_dict(self, x509_cert, filepath):
        cert = DotDict()
        cert.san = []
        cert.subject = self._get_cert_components(x509_cert.get_subject().get_components())
        cert.issuer = self._get_cert_components(x509_cert.get_issuer().get_components())

        cert.not_after = datetime.strptime(x509_cert.get_notAfter().decode(), self.CERT_DATE_PATTERN)
        cert.not_before = datetime.strptime(x509_cert.get_notBefore().decode(), self.CERT_DATE_PATTERN)
        cert.pubkey_size = x509_cert.get_pubkey().bits()
        # cert.serial_number = '{:02x}'.format(cert_data.get_serial_number())
        cert.serial_number = str(x509_cert.get_serial_number())
        cert.signature_algorithm = x509_cert.get_signature_algorithm().decode()

        for index in range(0, x509_cert.get_extension_count()):
            ext = x509_cert.get_extension(index)

            if 'subjectAltName' == ext.get_short_name().decode():
                ext_data = str(ext)
                if ext_data.startswith('DNS:'):
                    for dns_name in ext_data.split(','):
                        cert.san.append(dns_name.split(':')[1].strip())
            elif 'subjectKeyIdentifier' == ext.get_short_name().decode():
                cert.subject_key_identifier = str(ext)

        if 'sha1' in cert.signature_algorithm.lower():
            cert.sha1_fingerprint = x509_cert.digest('sha1').decode()
        elif 'sha2' in cert.signature_algorithm.lower():
            cert.sha2_fingerprint = x509_cert.digest('sha256').decode()
        elif 'md5' in cert.signature_algorithm.lower():
            cert.md5_fingerprint = x509_cert.digest('md5').decode()
        else:
            LOGGER.warning('Unknown signature "{}" in cert: "{}"'.format(cert.signature_algorithm, filepath))

        return cert

    def clear(self):
        raise NotImplemented()

    def clear_all_but_hosts(self):
        raise NotImplemented()

    def create_uid(self, _id):
        return '{}-{}'.format(_id, self._curr_file_hash)

    @classmethod
    def get_file_head(cls, filepath, num_of_lines):
        head = None
        try:
            with open(filepath, 'r') as file_handle:
                head = list(islice(file_handle, num_of_lines))
        except Exception:
            pass

        return head

    @classmethod
    def is_valid_file(cls, file):
        return True
