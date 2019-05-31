from vulnscan_parser.models.vsbase import VSBaseModel


# inheritance from VSCertificate does not apply here
class PemCertificate(VSBaseModel):

    def __init__(self):
        super().__init__()
        self.host = None
        self.service = None
        self.hostname = ''
        self.pem = ''
        self.serial_number = ''
        self.subject = {}
        self.issuer = {}
        self.pubkey_size = ''
        self.san = []
        self.signature_algorithm = ''
        self.not_before = ''
        self.not_after = ''
        self.sha1_fingerprint = ''
        self.sha2_fingerprint = ''
        self.md5_fingerprint = ''
        self.subject_key_identifier = ''

    @property
    def ip(self):
        return self.host.ip

    @property
    def protocol(self):
        return self.service.protocol

    @property
    def port(self):
        return self.service.port
